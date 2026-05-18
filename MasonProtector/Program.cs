using System;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

namespace MasonProtector
{
    internal static class Program
    {

        private const string EmbeddedDnlibResourceName =
            "MasonProtector.Embedded.dnlib.dll";

        private static byte[] _cachedDnlibBytes;

        [STAThread]
        static void Main()
        {
            AppDomain.CurrentDomain.AssemblyResolve += ResolveEmbeddedAssembly;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Builder());
        }

        private static Assembly ResolveEmbeddedAssembly(object sender, ResolveEventArgs e)
        {
            try
            {

                var requested = new AssemblyName(e.Name);
                if (!string.Equals(requested.Name, "dnlib", StringComparison.OrdinalIgnoreCase))
                    return null;

                if (requested.Name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
                    return null;

                byte[] bytes = _cachedDnlibBytes;
                if (bytes == null)
                {
                    var self = Assembly.GetExecutingAssembly();
                    using (Stream stm = self.GetManifestResourceStream(EmbeddedDnlibResourceName))
                    {
                        if (stm == null) return null;
                        bytes = new byte[stm.Length];
                        int read = 0, total = 0;
                        while ((read = stm.Read(bytes, total, bytes.Length - total)) > 0)
                            total += read;
                    }
                    _cachedDnlibBytes = bytes;
                }
                return Assembly.Load(bytes);
            }
            catch
            {

                return null;
            }
        }
    }
}

