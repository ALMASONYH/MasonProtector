using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace MasonProtector.Core
{
    internal static class Theme
    {

        public static Color Background    = Color.FromArgb(20, 18, 30);
        public static Color Surface       = Color.FromArgb(30, 26, 46);
        public static Color SurfaceAlt    = Color.FromArgb(42, 36, 64);
        public static Color Accent        = Color.FromArgb(138, 92, 245);
        public static Color AccentDark    = Color.FromArgb(96,  56, 200);
        public static Color Text          = Color.FromArgb(238, 238, 248);
        public static Color TextMuted     = Color.FromArgb(160, 156, 178);
        public static Color Danger        = Color.FromArgb(220, 70, 90);

        public static event Action AccentChanged;

        public static void SetAccent(Color c)
        {
            Accent = c;

            AccentDark = Darken(c, 0.35);
            Save();
            if (AccentChanged != null) AccentChanged();
        }

        private static Color Darken(Color c, double pct)
        {
            int r = (int)Math.Max(0, c.R * (1.0 - pct));
            int g = (int)Math.Max(0, c.G * (1.0 - pct));
            int b = (int)Math.Max(0, c.B * (1.0 - pct));
            return Color.FromArgb(c.A, r, g, b);
        }

        private static string ConfigPath
        {
            get
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "MasonProtector");
                try { Directory.CreateDirectory(dir); } catch { }
                return Path.Combine(dir, "theme.config");
            }
        }

        public static void Load()
        {
            try
            {
                if (!File.Exists(ConfigPath)) return;
                string txt = File.ReadAllText(ConfigPath).Trim();

                if (txt.Length >= 6)
                {

                    uint argbU = uint.Parse(txt, System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture);
                    var c = Color.FromArgb(unchecked((int)argbU));
                    Accent = c;
                    AccentDark = Darken(c, 0.35);
                }
            }
            catch { }
        }

        public static void Save()
        {
            try { File.WriteAllText(ConfigPath, Accent.ToArgb().ToString("X8")); }
            catch { }
        }

        public static void Apply(Control root)
        {
            if (root == null) return;
            ApplyToOne(root);
            foreach (Control child in root.Controls)
                Apply(child);
        }

        private static void ApplyToOne(Control c)
        {

            if (c is Form)
            {
                c.BackColor = Background;
                c.ForeColor = Text;
                return;
            }

            if (c is FlowLayoutPanel || c is Panel || c is TabPage)
            {
                c.BackColor = Surface;
                c.ForeColor = Text;
            }
            else
            {
                c.ForeColor = Text;
            }
        }

    }
}

