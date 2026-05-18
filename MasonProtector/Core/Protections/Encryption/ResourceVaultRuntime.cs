using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace MasonProtector.Core.RuntimeStubs
{
    internal static class ResourceVaultRuntime
    {
#pragma warning disable 0649
        internal static string _file;
        internal static byte[] _seed;
        internal static byte[] _mask1;
        internal static byte[] _mask2;
        internal static byte[] _off;
        internal static byte[] _tag;
        internal static byte[] _magic;
#pragma warning restore 0649

        private static Dictionary<string, byte[]> _entries;
        private static volatile int _state;
        private static readonly object _lock = new object();

        internal static Stream GetStream(Assembly asm, string name)
        {
            EnsureLoaded();
            var entries = _entries;
            if (entries != null && name != null)
            {
                byte[] data;
                if (entries.TryGetValue(name, out data))
                    return new MemoryStream(data, false);
            }
            if (asm != null) return asm.GetManifestResourceStream(name);
            return null;
        }

        private static void EnsureLoaded()
        {
            if (_state == 2) return;
            lock (_lock)
            {
                if (_state == 2) return;
                if (_state == 1)
                {

                    return;
                }
                _state = 1;
                try
                {
                    LoadCore();
                    System.Threading.Thread.MemoryBarrier();
                    _state = 2;
                }
                catch
                {

                    _entries = null;
                    System.Threading.Thread.MemoryBarrier();
                    _state = 0;
                }
            }
        }

        private static void LoadCore()
        {
            if (_file == null) return;
            if (_seed == null || _mask1 == null || _mask2 == null || _off == null || _tag == null) return;
            int seedLen = _seed.Length;
            if (seedLen < 176) return;
            if (_mask1.Length < seedLen || _mask2.Length < seedLen) return;
            if (_off.Length < 32) return;

            byte[] seed = new byte[seedLen];
            for (int i = 0; i < seedLen; i++)
            {
                int o1 = (i + _off[i & 0x1F]) % seedLen;
                int o2 = (i + _off[(i + 7) & 0x1F]) % seedLen;
                seed[i] = (byte)(_seed[i] ^ _mask1[o1] ^ _mask2[o2]);
            }

            byte[] ctrlKey    = Sub(seed, 0,   32);
            byte[] ctrlIv     = Sub(seed, 32,  16);
            byte[] indexKey   = Sub(seed, 48,  32);
            byte[] indexIv    = Sub(seed, 80,  16);
            byte[] dataMaster = Sub(seed, 96,  48);
            byte[] hmacKey    = Sub(seed, 144, 32);

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            if (string.IsNullOrEmpty(baseDir)) baseDir = ".";
            string path = Path.Combine(baseDir, _file + ".dll");
            if (!File.Exists(path)) return;

            byte[] file = File.ReadAllBytes(path);
            if (file.Length < 128) return;

            byte[] ctrlCipher = new byte[64];
            Buffer.BlockCopy(file, 64, ctrlCipher, 0, 64);

            byte[] ctrlMix = SeededStream(_tag, 0x41, 64);
            for (int i = 0; i < 64; i++) ctrlCipher[i] ^= ctrlMix[i];

            byte[] ctrlPlain = AesDecNoPad(ctrlCipher, ctrlKey, ctrlIv);
            if (ctrlPlain == null || ctrlPlain.Length < 20) return;
            if (_magic == null || _magic.Length < 4) return;
            if (ctrlPlain[0] != _magic[0] || ctrlPlain[1] != _magic[1] ||
                ctrlPlain[2] != _magic[2] || ctrlPlain[3] != _magic[3]) return;

            int count   = ReadInt(ctrlPlain, 4);
            int idxOff  = ReadInt(ctrlPlain, 8);
            int idxLen  = ReadInt(ctrlPlain, 12);
            int dataOff = ReadInt(ctrlPlain, 16);

            if (count <= 0 || count > 65536) return;
            if (idxOff <= 0 || idxLen <= 0 || idxLen > file.Length) return;
            if ((long)idxOff + idxLen > file.Length) return;
            if (dataOff <= 0 || dataOff > file.Length) return;

            byte[] idxCipher = new byte[idxLen];
            Buffer.BlockCopy(file, idxOff, idxCipher, 0, idxLen);

            byte[] idxMix = SeededStream(_tag, 0x53, idxLen);
            for (int i = 0; i < idxLen; i++) idxCipher[i] ^= idxMix[i];

            byte[] idxPlain = AesDec(idxCipher, indexKey, indexIv);
            if (idxPlain == null) return;

            Dictionary<string, byte[]> entries = new Dictionary<string, byte[]>(count, StringComparer.Ordinal);

            int p = 0;
            for (int i = 0; i < count; i++)
            {
                if (p + 7 > idxPlain.Length) return;
                int nameLen = idxPlain[p] | (idxPlain[p + 1] << 8); p += 2;
                if (nameLen < 0 || nameLen > 4096) return;
                if (p + nameLen + 1 + 4 + 4 + 16 + 32 + 32 > idxPlain.Length) return;

                string entryName = Encoding.UTF8.GetString(idxPlain, p, nameLen); p += nameLen;
                byte isReal = idxPlain[p]; p += 1;
                int dOff = ReadInt(idxPlain, p); p += 4;
                int dLen = ReadInt(idxPlain, p); p += 4;
                byte[] segIv      = Sub(idxPlain, p, 16); p += 16;
                byte[] segKeyMask = Sub(idxPlain, p, 32); p += 32;
                byte[] segHmac    = Sub(idxPlain, p, 32); p += 32;

                if (dLen <= 0 || (long)dataOff + dOff + dLen > file.Length) return;

                byte[] segCipher = new byte[dLen];
                Buffer.BlockCopy(file, dataOff + dOff, segCipher, 0, dLen);

                byte[] segStream = SeededStream(_tag, (byte)(0x91 ^ (i & 0x7F)), dLen);
                for (int k = 0; k < dLen; k++) segCipher[k] ^= segStream[k];

                byte[] segKey = DeriveSegmentKey(dataMaster, _tag, entryName, i);
                for (int k = 0; k < 32; k++) segKey[k] ^= segKeyMask[k];

                byte[] segPlain = AesDec(segCipher, segKey, segIv);
                Array.Clear(segKey, 0, segKey.Length);
                if (segPlain == null) return;

                if (isReal != 0)
                {
                    byte[] check;
                    using (HMACSHA256 h = new HMACSHA256(hmacKey))
                        check = h.ComputeHash(segPlain);
                    if (!ConstantTimeEqual(check, segHmac))
                        return;
                }

                if (isReal == 0) continue;

                byte[] segOut;
                using (MemoryStream ms = new MemoryStream(segPlain))
                using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Decompress))
                using (MemoryStream os = new MemoryStream())
                {
                    byte[] tmp = new byte[8192];
                    int n;
                    while ((n = ds.Read(tmp, 0, tmp.Length)) > 0)
                        os.Write(tmp, 0, n);
                    segOut = os.ToArray();
                }

                entries[entryName] = segOut;
            }

            _entries = entries;

            Array.Clear(seed,       0, seed.Length);
            Array.Clear(ctrlKey,    0, ctrlKey.Length);
            Array.Clear(indexKey,   0, indexKey.Length);
            Array.Clear(dataMaster, 0, dataMaster.Length);
            Array.Clear(hmacKey,    0, hmacKey.Length);
        }

        private static byte[] DeriveSegmentKey(byte[] dataMaster, byte[] tag, string entryName, int idx)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(entryName);
            int matLen = tag.Length + nameBytes.Length + 4;
            byte[] mat = new byte[matLen];
            Buffer.BlockCopy(tag, 0, mat, 0, tag.Length);
            Buffer.BlockCopy(nameBytes, 0, mat, tag.Length, nameBytes.Length);
            int j = tag.Length + nameBytes.Length;
            mat[j]     = (byte)(idx & 0xFF);
            mat[j + 1] = (byte)((idx >> 8) & 0xFF);
            mat[j + 2] = (byte)((idx >> 16) & 0xFF);
            mat[j + 3] = (byte)((idx >> 24) & 0xFF);

            byte[] k1;
            using (HMACSHA256 h = new HMACSHA256(dataMaster))
                k1 = h.ComputeHash(mat);
            byte[] k2;
            using (HMACSHA256 h = new HMACSHA256(k1))
                k2 = h.ComputeHash(tag);
            for (int i = 0; i < 32; i++) k1[i] ^= k2[i];
            Array.Clear(k2, 0, k2.Length);
            return k1;
        }

        private static bool ConstantTimeEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static byte[] AesDec(byte[] cipher, byte[] key, byte[] iv)
        {
            return AesDecCore(cipher, key, iv, PaddingMode.PKCS7);
        }

        private static byte[] AesDecNoPad(byte[] cipher, byte[] key, byte[] iv)
        {
            return AesDecCore(cipher, key, iv, PaddingMode.None);
        }

        private static byte[] AesDecCore(byte[] cipher, byte[] key, byte[] iv, PaddingMode pad)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = pad;
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Key = key;
                    aes.IV = iv;
                    using (ICryptoTransform dec = aes.CreateDecryptor())
                    using (MemoryStream ms = new MemoryStream(cipher))
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                    using (MemoryStream os = new MemoryStream())
                    {
                        byte[] tmp = new byte[4096];
                        int n;
                        while ((n = cs.Read(tmp, 0, tmp.Length)) > 0) os.Write(tmp, 0, n);
                        return os.ToArray();
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private static byte[] SeededStream(byte[] tag, byte salt, int length)
        {
            byte[] result = new byte[length];
            byte[] block;
            using (SHA256 sha = SHA256.Create())
            {
                byte[] mat = new byte[(tag != null ? tag.Length : 0) + 1];
                if (tag != null) Buffer.BlockCopy(tag, 0, mat, 0, tag.Length);
                mat[mat.Length - 1] = salt;
                block = sha.ComputeHash(mat);
            }
            int pos = 0;
            while (pos < length)
            {
                int take = length - pos;
                if (take > block.Length) take = block.Length;
                Buffer.BlockCopy(block, 0, result, pos, take);
                pos += take;
                if (pos < length)
                {
                    using (SHA256 sha = SHA256.Create()) block = sha.ComputeHash(block);
                }
            }
            return result;
        }

        private static byte[] Sub(byte[] src, int off, int len)
        {
            byte[] r = new byte[len];
            Buffer.BlockCopy(src, off, r, 0, len);
            return r;
        }

        private static int ReadInt(byte[] buf, int off)
        {
            return buf[off]
                 | (buf[off + 1] << 8)
                 | (buf[off + 2] << 16)
                 | (buf[off + 3] << 24);
        }
    }
}

