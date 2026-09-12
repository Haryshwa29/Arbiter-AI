using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

internal static class WindowsSetupLauncher
{
    [STAThread]
    private static int Main(string[] args)
    {
        string temp = Path.Combine(Path.GetTempPath(), "arbiter-install-" + Guid.NewGuid().ToString("N") + ".ps1");
        try
        {
            using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream("Arbiter.InstallScript"))
            {
                if (input == null) throw new InvalidOperationException("The embedded installer script is missing.");
                using (FileStream output = File.Create(temp)) input.CopyTo(output);
            }
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            string forwarded = "";
            foreach (string argument in args) forwarded += " " + Quote(argument);
            var info = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                        "WindowsPowerShell", "v1.0", "powershell.exe"),
                Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File " + Quote(temp) +
                            " -PortableRoot " + Quote(root) + forwarded,
                UseShellExecute = false
            };
            using (Process process = Process.Start(info))
            {
                process.WaitForExit();
                if (!Console.IsInputRedirected)
                {
                    Console.WriteLine();
                    Console.WriteLine(process.ExitCode == 0
                        ? "Installation finished. Press Enter to close."
                        : "Installation failed. Review the message above, then press Enter to close.");
                    Console.ReadLine();
                }
                return process.ExitCode;
            }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("Arbiter Setup could not start: " + error.Message);
            Console.WriteLine("Press Enter to close.");
            Console.ReadLine();
            return 1;
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }
}
