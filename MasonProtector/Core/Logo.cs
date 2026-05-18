using System;
using System.Drawing;
using System.Drawing.Drawing2D;

namespace MasonProtector.Core
{
    internal static class Logo
    {

        private static readonly System.Collections.Generic.Dictionary<long, Bitmap> _cache
            = new System.Collections.Generic.Dictionary<long, Bitmap>();

        public static Bitmap Get(int size)
        {
            long key = ((long)size << 32) | (uint)Theme.Accent.ToArgb();
            Bitmap bmp;
            if (_cache.TryGetValue(key, out bmp)) return bmp;
            bmp = Render(size);
            _cache[key] = bmp;
            return bmp;
        }

        public static string GetBase64Png(int size)
        {
            using (var bmp = Render(size))
            using (var ms = new System.IO.MemoryStream())
            {
                bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                return System.Convert.ToBase64String(ms.ToArray());
            }
        }

        public static void Invalidate()
        {

            _cache.Clear();
        }

        private static Bitmap Render(int size)
        {
            var bmp = new Bitmap(size, size);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;

                using (var hex = BuildHexagon(size))
                using (var fill = new LinearGradientBrush(
                           new Rectangle(0, 0, size, size),
                           Theme.Accent, Theme.AccentDark, 90f))
                {
                    g.FillPath(fill, hex);
                }

                using (var hex = BuildHexagon(size, 0.97f))
                using (var ring = new Pen(Color.FromArgb(220, Color.White), Math.Max(1f, size / 36f)))
                {
                    g.DrawPath(ring, hex);
                }

                using (var hexInner = BuildHexagon(size, 0.78f))
                using (var glow = new Pen(Color.FromArgb(70, Color.White), Math.Max(1f, size / 60f)))
                {
                    g.DrawPath(glow, hexInner);
                }

                using (var m = BuildLetterM(size))
                using (var mFill = new LinearGradientBrush(
                           new Rectangle(0, (int)(size * 0.25f), size, (int)(size * 0.55f)),
                           Color.White, Color.FromArgb(220, 220, 240), 90f))
                {
                    g.FillPath(mFill, m);
                    using (var mEdge = new Pen(Color.FromArgb(40, 30, 60), Math.Max(1f, size / 80f)))
                        g.DrawPath(mEdge, m);
                }
            }
            return bmp;
        }

        private static GraphicsPath BuildHexagon(int size, float scale = 0.92f)
        {
            var cx = size / 2f;
            var cy = size / 2f;
            float r = (size / 2f) * scale;
            var pts = new PointF[6];
            for (int i = 0; i < 6; i++)
            {
                double angle = (Math.PI / 3.0) * i + Math.PI / 6.0;
                pts[i] = new PointF(
                    (float)(cx + r * Math.Cos(angle)),
                    (float)(cy + r * Math.Sin(angle)));
            }
            var p = new GraphicsPath();
            p.AddPolygon(pts);
            return p;
        }

        private static GraphicsPath BuildLetterM(int size)
        {
            float u = size;

            var pts = new PointF[]
            {
                new PointF(0.26f * u, 0.74f * u),
                new PointF(0.26f * u, 0.30f * u),
                new PointF(0.36f * u, 0.30f * u),
                new PointF(0.50f * u, 0.58f * u),
                new PointF(0.64f * u, 0.30f * u),
                new PointF(0.74f * u, 0.30f * u),
                new PointF(0.74f * u, 0.74f * u),
                new PointF(0.66f * u, 0.74f * u),
                new PointF(0.66f * u, 0.46f * u),
                new PointF(0.54f * u, 0.70f * u),
                new PointF(0.46f * u, 0.70f * u),
                new PointF(0.34f * u, 0.46f * u),
                new PointF(0.34f * u, 0.74f * u),
            };
            var path = new GraphicsPath();
            path.AddPolygon(pts);
            return path;
        }
    }
}

