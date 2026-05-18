using System;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;

namespace MasonProtector.Core
{
    internal class HtmlView : Panel
    {
        private readonly WebBrowser _wb;
        private string _pendingHtml;
        private bool _ready;

        private object _pendingBridge;

        public event EventHandler DocumentReady;

        public HtmlView()
        {
            EnsureIE11Mode();
            _wb = new WebBrowser
            {
                Dock = DockStyle.Fill,
                ScrollBarsEnabled = true,

                IsWebBrowserContextMenuEnabled = true,
                WebBrowserShortcutsEnabled = true,

                AllowWebBrowserDrop = false,
                ScriptErrorsSuppressed = true,
            };
            _wb.DocumentCompleted += OnDocumentCompleted;
            _wb.Navigating += OnNavigating;
            this.Controls.Add(_wb);
        }

        private void OnNavigating(object sender, WebBrowserNavigatingEventArgs e)
        {

            if (e.Url == null) return;
            try
            {
                if (e.Url.AbsoluteUri != "about:blank" &&
                    !e.Url.AbsoluteUri.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
                {
                    e.Cancel = true;
                }
            }
            catch { }
        }

        public void LoadHtml(string html)
        {
            _pendingHtml = html ?? "";
            _ready = false;

            _wb.Navigate("about:blank");
        }

        public void RegisterBridge(object bridge)
        {
            _pendingBridge = bridge;

            try { _wb.ObjectForScripting = bridge; } catch { }
        }

        public void InvokeJs(string fn, params object[] args)
        {
            if (!_ready) return;
            try { _wb.Document.InvokeScript(fn, args); }
            catch {  }
        }

        private void OnDocumentCompleted(object sender, WebBrowserDocumentCompletedEventArgs e)
        {

            if (_pendingBridge != null)
            {
                try { _wb.ObjectForScripting = _pendingBridge; } catch { }
            }

            if (e.Url != null && e.Url.AbsoluteUri == "about:blank" && _pendingHtml != null)
            {
                string toWrite = _pendingHtml;
                _pendingHtml = null;
                try { _wb.Document.OpenNew(true); } catch { }
                try { _wb.Document.Write(toWrite); } catch { }
                try { _wb.Refresh(WebBrowserRefreshOption.Completely); } catch { }

                if (_pendingBridge != null)
                {
                    try { _wb.ObjectForScripting = _pendingBridge; } catch { }
                }
                return;
            }

            _ready = true;
            if (DocumentReady != null) DocumentReady(this, EventArgs.Empty);
        }

        private static bool _ie11Configured;
        private static void EnsureIE11Mode()
        {
            if (_ie11Configured) return;
            _ie11Configured = true;
            try
            {
                string exe = Path.GetFileName(Application.ExecutablePath);
                if (string.IsNullOrEmpty(exe)) return;
                using (var k = Registry.CurrentUser.CreateSubKey(
                           @"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"))
                {
                    if (k != null) k.SetValue(exe, 11001, RegistryValueKind.DWord);
                }

                using (var k = Registry.CurrentUser.CreateSubKey(
                           @"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"))
                {
                    if (k != null) k.SetValue(exe + ".vshost.exe", 11001, RegistryValueKind.DWord);
                }
            }
            catch {  }
        }
    }
}

