// Windows app entry point for the existing local Arbiter service.
// No embedded web engine, third-party runtime, credentials or remote URLs.
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

class DashboardLauncher {
    const string Origin = "http://127.0.0.1:8787";

    static bool Ready() {
        try {
            var request = (HttpWebRequest)WebRequest.Create(Origin + "/api/me");
            request.Proxy = null;
            request.Timeout = 1500;
            request.AllowAutoRedirect = false;
            HttpWebResponse response;
            try { response = (HttpWebResponse)request.GetResponse(); }
            catch (WebException error) {
                response = error.Response as HttpWebResponse;
                if (response == null || response.StatusCode != HttpStatusCode.Unauthorized) {
                    if (response != null) response.Dispose();
                    return false;
                }
            }
            using (response) {
                if (response.ContentType == null || !response.ContentType.StartsWith("application/json")) return false;
                using (var reader = new StreamReader(response.GetResponseStream())) {
                    var body = reader.ReadToEnd();
                    return body.Contains("\"role\"") || body.Contains("\"unauthenticated\"");
                }
            }
        } catch { return false; }
    }

    static int StartService() {
        var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe"), "/Run /TN Arbiter");
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        using (var process = Process.Start(info)) {
            process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            if (!process.WaitForExit(15000)) return 1;
            return process.ExitCode;
        }
    }

    static void OpenDashboard() {
        string[] candidates = {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft", "Edge", "Application", "msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft", "Edge", "Application", "msedge.exe")
        };
        foreach (string edge in candidates) {
            if (!File.Exists(edge)) continue;
            var info = new ProcessStartInfo(edge, "--app=" + Origin + "/overview --no-first-run --no-default-browser-check");
            info.UseShellExecute = false;
            Process.Start(info);
            return;
        }
        Process.Start(new ProcessStartInfo(Origin + "/overview") { UseShellExecute = true });
    }

    static void EnsureReady(CancellationToken cancellation) {
            if (!Ready()) {
                cancellation.ThrowIfCancellationRequested();
                if (StartService() != 0) {
                    // Only the existing service start needs elevation; the app window does not.
                    var start = new ProcessStartInfo(Application.ExecutablePath, "--start-service");
                    start.UseShellExecute = true;
                    start.Verb = "runas";
                    start.WindowStyle = ProcessWindowStyle.Hidden;
                    using (var process = Process.Start(start)) {
                        if (!process.WaitForExit(30000) || process.ExitCode != 0)
                            throw new Exception("Could not start the installed Arbiter service.");
                    }
                }
                var deadline = DateTime.UtcNow.AddSeconds(180);
                while (!Ready()) {
                    cancellation.ThrowIfCancellationRequested();
                    if (DateTime.UtcNow >= deadline) throw new Exception("Arbiter has not become ready. Check its service logs or restart the app shortly.");
                    Thread.Sleep(500);
                }
            }
    }

    class StartupWindow : Form {
        readonly Label status = new Label();
        readonly Button retry = new Button();
        readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        bool running;

        public StartupWindow() {
            Text = "Starting Arbiter AI";
            Width = 460; Height = 200;
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            status.SetBounds(24, 24, 392, 74);
            status.Text = "Starting your local security dashboard...\nWindows may ask for permission to start the background service.";
            status.AutoSize = false;
            retry.SetBounds(24, 110, 130, 32);
            retry.Text = "Try again"; retry.Visible = false;
            retry.Click += delegate { BeginStartup(); };
            Controls.Add(status); Controls.Add(retry);
            Shown += delegate { BeginStartup(); };
            FormClosed += delegate { cancellation.Cancel(); };
        }

        async void BeginStartup() {
            if (running) return;
            running = true; retry.Visible = false;
            status.Text = "Opening Arbiter AI...\nThe background service may take a few minutes to start.";
            try {
                await Task.Run(() => EnsureReady(cancellation.Token));
                if (cancellation.IsCancellationRequested) return;
                OpenDashboard();
                Close();
            } catch (OperationCanceledException) { }
            catch (Exception error) {
                if (cancellation.IsCancellationRequested) return;
                status.Text = error.Message;
                retry.Visible = true;
            } finally { running = false; }
        }
    }

    [STAThread]
    static int Main(string[] args) {
        try {
            if (args.Length == 1 && args[0] == "--check") return Ready() ? 0 : 2;
            if (args.Length == 1 && args[0] == "--start-service") return StartService();
            if (args.Length != 0) throw new Exception("Unsupported launcher option.");
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new StartupWindow());
            return 0;
        } catch (Exception error) {
            MessageBox.Show(error.Message, "Arbiter AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 1;
        }
    }
}
