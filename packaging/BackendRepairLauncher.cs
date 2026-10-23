using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

class BackendRepairLauncher {
    [STAThread]
    static int Main() {
        Console.Title = "Repairing Arbiter AI";
        string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "backend-repair");
        try {
            string script = Path.Combine(root, "Repair-Backend.ps1");
            if (!File.Exists(script)) throw new Exception("The repair files are missing. Keep the complete Arbiter AI folder together.");
            Console.WriteLine("Repairing your existing Arbiter AI installation.");
            Console.WriteLine("Your accounts, settings and history will be preserved.");
            Console.WriteLine("Please keep this window open. Startup checks can take up to five minutes.");
            var info = new ProcessStartInfo(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                "-NoLogo -NoProfile -File \"" + script + "\"");
            info.WorkingDirectory = root;
            info.UseShellExecute = false;
            using (var process = Process.Start(info)) {
                while (!process.WaitForExit(1000)) Console.Write(".");
                Console.WriteLine();
                if (process.ExitCode != 0) throw new Exception("The repair could not finish. Details are saved in " + root);
            }
            MessageBox.Show("The backend passed its checks. Close the old dashboard window, then open Arbiter AI from your desktop.", "Arbiter AI repaired", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        } catch (Exception error) {
            Console.WriteLine(error.Message);
            MessageBox.Show(error.Message, "Arbiter repair", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return 1;
        }
    }
}
