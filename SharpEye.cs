using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SharpEye
{
    public class Watcher : IDisposable
    {
        private Stopwatch _stopwatch = new Stopwatch();
        private Action<TimeSpan> _callback;
        public Watcher()
        {
            _stopwatch.Start();
        }
        public Watcher(Action<TimeSpan> callback) : this()
        {
            _callback = callback;
        }

        public static Watcher Start(Action<TimeSpan> callback)
        {
            return new Watcher(callback);
        }
        public void Dispose()
        {
            _stopwatch.Stop();
            if (_callback != null)
                _callback(_stopwatch.Elapsed);
        }
    }
    class Program
    {
        static string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        static MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
        static Encoding enc = ASCIIEncoding.ASCII;
        private static void ScanFile(string path)
        {
            Process scanProcess = new Process();
            var mpcmdrun = new ProcessStartInfo(@"C:\Program Files\Windows Defender\MpCmdRun.exe")
            {
                Arguments = $"-Scan -ScanType 3 -File \"{path}\" -DisableRemediation -Trace -Level 0x10",
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            scanProcess.StartInfo = mpcmdrun;
            scanProcess.Start();
            scanProcess.WaitForExit(30000);
            if (!scanProcess.HasExited)
            {
                scanProcess.Kill();
                Alert("ERROR: Failed to scan file - timed out 30000s.");
                return;
            }
            string scanOutput;
            while ((scanOutput = scanProcess.StandardOutput.ReadLine()) != null)
            {
                if (scanOutput.Contains("Threat "))
                {
                    Alert($"THREAT: windows defender identified file {path} as malicious");
                    Alert($"Scan output: {scanOutput}");
                    Alert($"Adding file hash to collection, Deleting file {path}...");
                    File.Delete(path);
                    scanProcess.Kill();
                    // add to database 
                    return;
                }
            }
        }
        private static bool isInDatabase(string path, string[] hashes)
        {
            byte[] currHash = md5.ComputeHash(File.ReadAllBytes(path));
            return Array.IndexOf(hashes, enc.GetString(currHash)) != -1;
            // indexOf returns -1 if it can't find the item in the array
        }
        private static bool IsFileSuspicious(string path)
        {
            FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(path);
            string comments = versionInfo.Comments;
            if (comments.Contains("payload") || comments.Contains("Payload") || comments.Contains("RAT"))
            {
                return true;
            }
            if (versionInfo.CompanyName == string.Empty && Path.GetExtension(path) == ".exe")
                return true;
            return false;
        }
        private static void ScanDir(string path, string hashesPath)
        {
            string[] hashes = File.ReadAllLines(hashesPath);
            DirectoryInfo dir = new DirectoryInfo(path);
            foreach (FileInfo file in dir.GetFiles())
            {
                string filePath = file.FullName;
                if (IsFileSuspicious(filePath))
                {
                    Alert($"file {file.Name} seems suspicious...");
                    if (!isInDatabase(filePath,hashes))
                        ScanFile(filePath);
                    else
                    {
                        Console.WriteLine("found copy of a malicious file...");
                        File.Delete(filePath);
                    }
                }
            }
        }
        private static void CreateLog(string path,string logPath, bool update = false)
        {
            if (!update)
            {
                File.Create(logPath);
                File.SetAttributes(logPath, FileAttributes.Hidden);
            }
            List<string> times = new List<string>();

            DirectoryInfo dir = new DirectoryInfo(path);
            foreach (FileInfo file in dir.GetFiles())
            {
                if (file.IsReadOnly)
                    continue; 
                times.Add(file.LastAccessTimeUtc.ToString("F"));
            }

            File.WriteAllLines(logPath, times.ToArray());

        }
        static bool AlertForAccess(string path)
        {
            string logPath = Path.Combine(baseDir,"logAccessTime.txt");
            if (!File.Exists(logPath)){
                CreateLog(path,logPath); return false;
            }
            int count = 0;
            string[] times = File.ReadAllLines(logPath);
            DirectoryInfo dir = new DirectoryInfo(path);
            foreach (FileInfo file in dir.GetFiles())
            {
                if (file.IsReadOnly)
                    continue;
                if (file.LastAccessTimeUtc.ToString("F") != times[count++])
                {
                    Alert($"since last file check {file.Name} has been accessed, did you access it?");
                }
            }
            CreateLog(path, logPath, true);
            return true;

        }
        static string AskForPath()
        {
            Console.WriteLine("Please supply the full path for the directory to scan");
            return Console.ReadLine();
        }
        static void Alert(string message, bool errornous = true)
        {
            Console.ForegroundColor = (errornous == true) ? ConsoleColor.Red : ConsoleColor.Yellow;
            Console.WriteLine(message);
            Console.ResetColor();
        }
        static void Main(string[] args)
        {
            string hashesFilesDir = Path.Combine(baseDir, "hashes");
            if (Directory.Exists(hashesFilesDir))
            {
                Directory.CreateDirectory(hashesFilesDir);
            }
            string path;
            if (args.Length < 1)
                path = AskForPath();
            else
                path = args[0];
            while (!Directory.Exists(path))
            {
                Alert("ERROR: Couldn't find the path specified");
                path = AskForPath();
            }
            byte[] hashAsBytes = md5.ComputeHash(enc.GetBytes(path));
            string hashesPath = Path.Combine(
                hashesFilesDir, enc.GetString(hashAsBytes) + ".txt");
            if (File.Exists(hashesPath)){
                File.Create(hashesPath);
                File.SetAttributes(hashesPath, FileAttributes.Hidden);
            }
            if (!AlertForAccess(path))
            {
                Alert("Couldn't locate log file, is this your first time testing this directory?", false);
            }
            using (Watcher.Start(ts => Console.WriteLine($"Completed Scan in {ts.TotalSeconds} seconds")))
            {
                ScanDir(path,hashesPath);

            }
            // implement workers cause we're potentially scanning a lot of files and it shouldn't take forever
            // also ask for privilege otherwise the program can't actually do anything

                
        }
    }
}
