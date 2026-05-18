using System;
using System.Runtime.InteropServices;

namespace MasonProtector.Core
{

    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.AutoDispatch)]
    public class AppBridge
    {
        [ComVisible(false)] public Action OnWindowDrag      { get; set; }
        [ComVisible(false)] public Action OnWindowMinimize  { get; set; }
        [ComVisible(false)] public Action OnWindowMaximize  { get; set; }
        [ComVisible(false)] public Action OnWindowClose     { get; set; }

        [ComVisible(false)] public Action<string, bool>   OnSetBoolOption  { get; set; }
        [ComVisible(false)] public Action<string, int>    OnSetIntOption   { get; set; }
        [ComVisible(false)] public Action<string, string> OnSetTextOption  { get; set; }
        [ComVisible(false)] public Action<bool>           OnSetEnableAll   { get; set; }

        [ComVisible(false)] public Action       OnBrowse         { get; set; }
        [ComVisible(false)] public Action       OnProtect        { get; set; }
        [ComVisible(false)] public Action       OnScanLibraries  { get; set; }
        [ComVisible(false)] public Action<int, bool> OnToggleLibrary { get; set; }

        [ComVisible(false)] public Action       OnPickColor      { get; set; }
        [ComVisible(false)] public Action       OnResetTheme     { get; set; }
        [ComVisible(false)] public Action<int, int, int> OnApplyColor { get; set; }

        [ComVisible(false)] public Action<string> OnLog          { get; set; }

        [ComVisible(false)] public Func<string>           OnScanTarget  { get; set; }
        [ComVisible(false)] public Action<string, bool>   OnSetExcluded { get; set; }

        [ComVisible(false)] public Action<string>         OnOpenUrl     { get; set; }

        public void WindowDrag()     { Try(OnWindowDrag); }
        public void WindowMinimize() { Try(OnWindowMinimize); }
        public void WindowMaximize() { Try(OnWindowMaximize); }
        public void WindowClose()    { Try(OnWindowClose); }

        public void SetOption(string name, bool value)
        {
            try { var h = OnSetBoolOption; if (h != null) h(name, value); } catch { }
        }
        public void SetNumeric(string name, int value)
        {
            try { var h = OnSetIntOption; if (h != null) h(name, value); } catch { }
        }
        public void SetText(string name, string value)
        {
            try { var h = OnSetTextOption; if (h != null) h(name, value ?? ""); } catch { }
        }
        public void EnableAll(bool value)
        {
            try { var h = OnSetEnableAll; if (h != null) h(value); } catch { }
        }

        public void Browse()        { Try(OnBrowse); }
        public void Protect()       { Try(OnProtect); }
        public void ScanLibraries() { Try(OnScanLibraries); }
        public void ToggleLibrary(int index, bool isChecked)
        {
            try { var h = OnToggleLibrary; if (h != null) h(index, isChecked); } catch { }
        }

        public void PickColor()  { Try(OnPickColor); }
        public void ResetTheme() { Try(OnResetTheme); }
        public void ApplyColor(int r, int g, int b)
        {
            try { var h = OnApplyColor; if (h != null) h(r, g, b); } catch { }
        }

        public void Log(string msg)
        {
            try { var h = OnLog; if (h != null) h(msg ?? ""); } catch { }
        }

        public string ScanTarget()
        {
            try { var h = OnScanTarget; if (h != null) return h() ?? ""; } catch { }
            return "";
        }
        public void SetExcluded(string fullName, bool excluded)
        {
            try { var h = OnSetExcluded; if (h != null) h(fullName ?? "", excluded); } catch { }
        }
        public void OpenUrl(string url)
        {
            try { var h = OnOpenUrl; if (h != null) h(url ?? ""); } catch { }
        }

        private static void Try(Action a)
        {
            try { if (a != null) a(); } catch { }
        }
    }
}

