using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;

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
        private static void ScanWithAntivirus(string path)
        {

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
        private static void ScanDir(string path)
        {
            DirectoryInfo dir = new DirectoryInfo(path);
            foreach (FileInfo file in dir.GetFiles())
            {
                string filePath = file.FullName;
                if (IsFileSuspicious(filePath))
                {
                    Alert($"file {file.Name} seems suspicious...");
                    ScanWithAntivirus(filePath);
                }
            }
        }
        private static void CreateLog(string path, bool update = false)
        {
            string logPath = Path.Combine(path, "LogAccessTime.txt");
            if (!update)
            {
                File.Create(logPath);
                File.SetAttributes(logPath, FileAttributes.Hidden | File.GetAttributes(logPath));
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
            string logPath = Path.Combine(path, "LogAccessTime.txt");
            if (!File.Exists(logPath)){
                CreateLog(path); return false;
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
            if (!AlertForAccess(path))
            {
                Alert("Couldn't locate log file, is this your first time testing this directory?", false);
            }
            using (Watcher.Start(ts => Console.WriteLine($"Completed Scan in {ts.TotalSeconds} seconds")))
            {
                ScanDir(path);

            }
            // add interaction with windows defender 
            // maybe encrypt the log file too? 
            Console.WriteLine("Updating log file with last access dates...");
            CreateLog(Path.Combine(path, "LogAccessTime.txt"), true);

                
        }
    }
}

