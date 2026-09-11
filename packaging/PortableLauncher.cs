// Small Windows entry point. All application behavior stays in readable Python.
using System;
using System.Diagnostics;
using System.IO;

class PortableLauncher {
    static int Main(string[] args) {
        string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
        string python = Path.Combine(root, "runtime", "python", "python.exe");
        string app = Path.Combine(root, "app", "arbiter.pyz");
        try {
            if (!File.Exists(python) || !File.Exists(app))
                throw new Exception("Copy the complete Arbiter folder, not just this EXE.");
            string options = "";
#if STOP
            options += " --stop";
#endif
            foreach (string arg in args) {
                if (arg == "--check" || arg == "--no-browser") options += " " + arg;
                else throw new Exception("Unsupported option: " + arg);
            }
            var start = new ProcessStartInfo(python,
                "-I -u \"" + app + "\" --portable --root \"" + root + "\"" + options);
            start.UseShellExecute = false;
            start.WorkingDirectory = root;
            using (var process = Process.Start(start)) {
                process.WaitForExit();
                int code = process.ExitCode;
                if (code != 0 && !Console.IsInputRedirected) {
                    Console.WriteLine("Press Enter to close."); Console.ReadLine();
                }
                return code;
            }
        } catch (Exception error) {
            Console.Error.WriteLine(error.Message);
            if (!Console.IsInputRedirected) Console.ReadLine();
            return 1;
        }
    }
}
