using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;

namespace MasonProtector.Core.RuntimeStubs
{
    internal static class BodyVaultRuntime
    {
        internal static string _resName = "$bv";

#pragma warning disable 0649
        internal static byte[] _pepper;

        internal static int _iters;
#pragma warning restore 0649

        private static byte[] _blob;
        private static int[] _entryOff;
        private static object _lock = new object();

        internal static RuntimeMethodHandle[] _mh  = new RuntimeMethodHandle[0];
        internal static RuntimeTypeHandle[]   _dh  = new RuntimeTypeHandle[0];
        internal static RuntimeFieldHandle[]  _fh  = new RuntimeFieldHandle[0];
        internal static RuntimeTypeHandle[]   _fdh = new RuntimeTypeHandle[0];
        internal static RuntimeTypeHandle[]   _th  = new RuntimeTypeHandle[0];
        internal static string[]              _us  = new string[0];

        internal static object Run(int idx, RuntimeMethodHandle handle, object[] args)
        {

            int hostileScore = 0;
            try { if (Debugger.IsAttached) hostileScore ^= 0x4A7B2C19; } catch { }
            try { if (Debugger.IsLogging()) hostileScore ^= 0x6F381D52; } catch { }
            try
            {
                string p = Environment.GetEnvironmentVariable("COR_PROFILER");
                if (!string.IsNullOrEmpty(p)) hostileScore ^= 0x1E3D8A47;
                p = Environment.GetEnvironmentVariable("CORECLR_PROFILER");
                if (!string.IsNullOrEmpty(p)) hostileScore ^= 0x5C92B16E;
                p = Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING");
                if (!string.IsNullOrEmpty(p) && p != "0") hostileScore ^= 0x7A4F0E83;
            }
            catch { }

            try { if (Debugger.IsAttached) hostileScore ^= unchecked((int)0x8B6E4F25); } catch { }
            bool ok = (hostileScore == 0);

            if (!ok)
            {
                try { WipeSensitiveState(); } catch { }
                return FakeReturnForHandle(handle);
            }
            EnsureLoaded();
            if (idx < 0 || idx >= _entryOff.Length)
                throw new IndexOutOfRangeException();
            int meta = _entryOff[idx];

            int codeOff     = ReadInt32(_blob, meta);
            int codeLen     = ReadInt32(_blob, meta + 4);
            int locOff      = ReadInt32(_blob, meta + 8);
            int locLen      = ReadInt32(_blob, meta + 12);
            int maxStack    = ReadInt32(_blob, meta + 16);
            int tokenOff    = ReadInt32(_blob, meta + 20);
            int tokenCount  = ReadInt32(_blob, meta + 24);
            int ehOff       = ReadInt32(_blob, meta + 28);
            int ehCount     = ReadInt32(_blob, meta + 32);

            MethodBase orig = MethodBase.GetMethodFromHandle(handle);
            Module mod = orig.Module;
            MethodInfo origMi = orig as MethodInfo;
            Type retType = origMi != null ? origMi.ReturnType : typeof(void);
            ParameterInfo[] pars = orig.GetParameters();
            bool needsThis = !orig.IsStatic;
            int extra = needsThis ? 1 : 0;
            Type[] paramTypes = new Type[pars.Length + extra];
            if (needsThis) paramTypes[0] = orig.DeclaringType;
            for (int i = 0; i < pars.Length; i++)
                paramTypes[i + extra] = pars[i].ParameterType;

            byte[] code = new byte[codeLen];
            Buffer.BlockCopy(_blob, codeOff, code, 0, codeLen);

            byte[] localSig = null;
            if (locLen > 0)
            {
                localSig = new byte[locLen];
                Buffer.BlockCopy(_blob, locOff, localSig, 0, locLen);
            }

            DynamicMethod dm = new DynamicMethod(
                "_bv_" + idx.ToString("X8"),
                retType, paramTypes, mod, true);
            DynamicILInfo info = dm.GetDynamicILInfo();

            for (int t = 0; t < tokenCount; t++)
            {
                int siteOff = ReadInt32(_blob, tokenOff + t * 4);
                int sent    = ReadInt32(code, siteOff);
                int dstTok  = ResolveSentinel(mod, info, sent);
                WriteInt32(code, siteOff, dstTok);
            }

            byte[] rebuiltSig;
            if (localSig != null) rebuiltSig = RebuildLocalSig(localSig);
            else                  rebuiltSig = new byte[] { 0x07, 0x00 };
            info.SetLocalSignature(rebuiltSig);
            info.SetCode(code, maxStack);

            if (ehCount > 0)
            {
                int ehBlobLen = 4 + ehCount * 24;
                byte[] ehBlob = new byte[ehBlobLen];
                ehBlob[0] = 0x41;
                ehBlob[1] = (byte)(ehBlobLen        & 0xFF);
                ehBlob[2] = (byte)((ehBlobLen >> 8) & 0xFF);
                ehBlob[3] = (byte)((ehBlobLen >> 16) & 0xFF);
                int srcRecLen = 28;
                for (int e = 0; e < ehCount; e++)
                {
                    int srcOff = ehOff + e * srcRecLen;
                    int dstOff = 4 + e * 24;
                    int flags         = ReadInt32(_blob, srcOff);
                    int tryStart      = ReadInt32(_blob, srcOff + 4);
                    int tryLen        = ReadInt32(_blob, srcOff + 8);
                    int handlerStart  = ReadInt32(_blob, srcOff + 12);
                    int handlerLen    = ReadInt32(_blob, srcOff + 16);
                    int filterStart   = ReadInt32(_blob, srcOff + 20);
                    int catchTypeSent = ReadInt32(_blob, srcOff + 24);

                    int classOrFilter;
                    if (flags == 0)
                        classOrFilter = ResolveSentinel(mod, info, catchTypeSent);
                    else if (flags == 1)
                        classOrFilter = filterStart;
                    else
                        classOrFilter = 0;

                    WriteInt32(ehBlob, dstOff,      flags);
                    WriteInt32(ehBlob, dstOff +  4, tryStart);
                    WriteInt32(ehBlob, dstOff +  8, tryLen);
                    WriteInt32(ehBlob, dstOff + 12, handlerStart);
                    WriteInt32(ehBlob, dstOff + 16, handlerLen);
                    WriteInt32(ehBlob, dstOff + 20, classOrFilter);
                }
                info.SetExceptions(ehBlob);
            }

            try
            {
                object result = dm.Invoke(null, args);

                Array.Clear(code, 0, code.Length);
                return result;
            }
            catch (TargetInvocationException tie)
            {
                Exception inner = tie.InnerException;
                if (inner == null) throw;

                try { TryPreserveStack(inner); } catch { }
                throw inner;
            }
        }

        private static void TryPreserveStack(Exception inner)
        {
            try
            {
                Type edi = Type.GetType("System.Runtime.ExceptionServices.ExceptionDispatchInfo, mscorlib", false);
                if (edi == null) return;
                MethodInfo cap = edi.GetMethod("Capture", BindingFlags.Public | BindingFlags.Static);
                MethodInfo thr = edi.GetMethod("Throw", BindingFlags.Public | BindingFlags.Instance);
                if (cap == null || thr == null) return;
                object info = cap.Invoke(null, new object[] { inner });
                thr.Invoke(info, null);
            }
            catch { }
        }

        private static int ResolveSentinel(Module mod, DynamicILInfo info, int sent)
        {
            if (((uint)sent & 0x80000000u) != 0)
            {
                int kind = (sent >> 24) & 0x7F;
                int idx  = sent & 0xFFFFFF;

                switch (kind)
                {
                    case 0:
                        if (idx < 0 || idx >= _mh.Length || _mh[idx].Value == IntPtr.Zero)
                            throw new MissingMethodException();
                        return info.GetTokenFor(_mh[idx], _dh[idx]);
                    case 1:
                        if (idx < 0 || idx >= _fh.Length || _fh[idx].Value == IntPtr.Zero)
                            throw new MissingFieldException();
                        return info.GetTokenFor(_fh[idx], _fdh[idx]);
                    case 2:
                        if (idx < 0 || idx >= _th.Length || _th[idx].Value == IntPtr.Zero)
                            throw new TypeLoadException();
                        return info.GetTokenFor(_th[idx]);
                    case 3:
                        if (idx < 0 || idx >= _us.Length || _us[idx] == null)
                            throw new InvalidOperationException();
                        return info.GetTokenFor(_us[idx]);
                    default: return sent;
                }
            }
            try
            {
                MethodBase mb = mod.ResolveMethod(sent);
                ConstructorInfo ci = mb as ConstructorInfo;
                if (ci != null) return info.GetTokenFor(ci.MethodHandle);
                MethodInfo mi = mb as MethodInfo;
                if (mi != null) return info.GetTokenFor(mi.MethodHandle);
            }
            catch { }
            try
            {
                FieldInfo fi = mod.ResolveField(sent);
                return info.GetTokenFor(fi.FieldHandle);
            }
            catch { }
            try
            {
                Type tp = mod.ResolveType(sent);
                return info.GetTokenFor(tp.TypeHandle);
            }
            catch { }
            try
            {
                string s = mod.ResolveString(sent);
                return info.GetTokenFor(s);
            }
            catch { }
            return sent;
        }

        private static byte[] RebuildLocalSig(byte[] enc)
        {
            int p = 0;
            if (enc.Length < 1 || enc[p] != 0x07)
                throw new InvalidOperationException("locsig header missing");
            p++;
            uint count = ReadCompressedUInt(enc, ref p);
            SignatureHelper sh = SignatureHelper.GetLocalVarSigHelper();
            for (uint i = 0; i < count; i++)
            {
                bool pinned;
                Type t = DecodeOneType(enc, ref p, out pinned);
                sh.AddArgument(t, pinned);
            }
            return sh.GetSignature();
        }

        private static Type DecodeOneType(byte[] enc, ref int p, out bool pinned)
        {
            pinned = false;
            while (enc[p] == 0x45)
            {
                pinned = true;
                p++;
            }
            byte et = enc[p++];
            switch (et)
            {
                case 0x01: return typeof(void);
                case 0x02: return typeof(bool);
                case 0x03: return typeof(char);
                case 0x04: return typeof(sbyte);
                case 0x05: return typeof(byte);
                case 0x06: return typeof(short);
                case 0x07: return typeof(ushort);
                case 0x08: return typeof(int);
                case 0x09: return typeof(uint);
                case 0x0A: return typeof(long);
                case 0x0B: return typeof(ulong);
                case 0x0C: return typeof(float);
                case 0x0D: return typeof(double);
                case 0x0E: return typeof(string);
                case 0x16: return typeof(TypedReference);
                case 0x18: return typeof(IntPtr);
                case 0x19: return typeof(UIntPtr);
                case 0x1C: return typeof(object);

                case 0x0F:
                {
                    bool _;
                    return DecodeOneType(enc, ref p, out _).MakePointerType();
                }
                case 0x10:
                {
                    bool _;
                    return DecodeOneType(enc, ref p, out _).MakeByRefType();
                }
                case 0x1D:
                {
                    bool _;
                    return DecodeOneType(enc, ref p, out _).MakeArrayType();
                }

                case 0x11:
                case 0x12:
                {
                    int sent = ReadInt32(enc, p); p += 4;
                    if (((uint)sent & 0x80000000u) == 0)
                        throw new InvalidOperationException(
                            "RebuildLocalSig: missing type sentinel at offset " + (p - 4));
                    int idx = sent & 0xFFFFFF;
                    if (idx < 0 || idx >= _th.Length)
                        throw new InvalidOperationException(
                            "RebuildLocalSig: type sentinel index " + idx +
                            " out of range (max " + _th.Length + ")");
                    if (_th[idx].Value == IntPtr.Zero)
                        throw new InvalidOperationException(
                            "RebuildLocalSig: type slot " + idx + " unresolved -- " +
                            "the populator chunk for this slot failed to load its " +
                            "referenced type at runtime; the original method's locals " +
                            "include a type whose declaring assembly cannot be loaded.");
                    Type result = Type.GetTypeFromHandle(_th[idx]);
                    if (result == null)
                        throw new InvalidOperationException(
                            "RebuildLocalSig: GetTypeFromHandle returned null for slot " + idx);
                    return result;
                }

                case 0x14:
                {
                    bool _;
                    Type inner = DecodeOneType(enc, ref p, out _);
                    uint rank = ReadCompressedUInt(enc, ref p);
                    uint nSizes = ReadCompressedUInt(enc, ref p);
                    for (uint i = 0; i < nSizes; i++) ReadCompressedUInt(enc, ref p);
                    uint nLos = ReadCompressedUInt(enc, ref p);
                    for (uint i = 0; i < nLos; i++) ReadCompressedInt(enc, ref p);
                    return inner.MakeArrayType((int)rank);
                }

                default:
                    throw new InvalidOperationException(
                        "RebuildLocalSig: unsupported element 0x" + et.ToString("X2") +
                        " at offset " + (p - 1));
            }
        }

        private static uint ReadCompressedUInt(byte[] b, ref int p)
        {
            byte b0 = b[p];
            if ((b0 & 0x80) == 0)
            {
                p++;
                return b0;
            }
            if ((b0 & 0xC0) == 0x80)
            {
                uint v = (uint)((b0 & 0x3F) << 8) | b[p + 1];
                p += 2;
                return v;
            }
            uint w = (uint)((b0 & 0x1F) << 24)
                   | (uint)(b[p + 1] << 16)
                   | (uint)(b[p + 2] <<  8)
                   |  b[p + 3];
            p += 4;
            return w;
        }

        private static void WriteCompressedUInt(Stream s, uint v)
        {
            if (v <= 0x7F) { s.WriteByte((byte)v); return; }
            if (v <= 0x3FFF)
            {
                s.WriteByte((byte)((v >> 8) | 0x80));
                s.WriteByte((byte)(v & 0xFF));
                return;
            }
            s.WriteByte((byte)((v >> 24) | 0xC0));
            s.WriteByte((byte)((v >> 16) & 0xFF));
            s.WriteByte((byte)((v >> 8)  & 0xFF));
            s.WriteByte((byte)(v & 0xFF));
        }

        private static int ReadCompressedInt(byte[] b, ref int p)
        {
            uint u = ReadCompressedUInt(b, ref p);
            bool neg = (u & 1) != 0;
            int mag = (int)(u >> 1);
            return neg ? -mag : mag;
        }

        private static void WriteCompressedInt(Stream s, int v)
        {
            uint u;
            if (v >= 0) u = (uint)v << 1;
            else        u = (uint)(((-v) << 1) | 1);
            WriteCompressedUInt(s, u);
        }

        private static void EnsureLoaded()
        {
            if (_blob != null) return;
            lock (_lock)
            {
                if (_blob != null) return;

                Assembly asm = typeof(BodyVaultRuntime).Assembly;
                Stream stm = asm.GetManifestResourceStream(_resName);
                if (stm == null)
                    throw new FileNotFoundException();
                byte[] raw;
                using (MemoryStream ms = new MemoryStream())
                {
                    stm.CopyTo(ms);
                    raw = ms.ToArray();
                }
                if (raw.Length < 65)
                    throw new EndOfStreamException();

                byte[] salt = new byte[16];
                Buffer.BlockCopy(raw, 0, salt, 0, 16);

                byte[] scrambledIv  = new byte[16];
                byte[] scrambledKey = new byte[32];
                Buffer.BlockCopy(raw, 16, scrambledIv,  0, 16);
                Buffer.BlockCopy(raw, 32, scrambledKey, 0, 32);
                byte wrappedXor = raw[64];

                int padLen = (salt[0] & 0x3F) + 1;
                int macStart = 65 + padLen;
                int sealedStart = macStart + 32;
                if (raw.Length <= sealedStart)
                    throw new EndOfStreamException();
                byte[] storedMac = new byte[32];
                Buffer.BlockCopy(raw, macStart, storedMac, 0, 32);
                int sealedLen = raw.Length - sealedStart;
                byte[] enc = new byte[sealedLen];
                Buffer.BlockCopy(raw, sealedStart, enc, 0, sealedLen);

                byte[] effectivePepper;
                {
                    string envName = "";
                    try
                    {
                        Assembly entry = Assembly.GetEntryAssembly();
                        if (entry != null) envName = entry.GetName().Name ?? "";
                    }
                    catch { }
                    byte[] envSeed = System.Text.Encoding.UTF8.GetBytes("bvenv:" + envName);
                    byte[] envMask;
                    using (var sh = SHA256.Create())
                        envMask = sh.ComputeHash(envSeed);
                    effectivePepper = new byte[_pepper.Length];
                    for (int i = 0; i < effectivePepper.Length; i++)
                        effectivePepper[i] = (byte)(_pepper[i] ^ envMask[i % envMask.Length]);
                    Array.Clear(envMask, 0, envMask.Length);
                }
                byte[] password;
                using (HMACSHA256 hm = new HMACSHA256(effectivePepper))
                    password = hm.ComputeHash(salt);
                Array.Clear(effectivePepper, 0, effectivePepper.Length);

                byte[] mask;
                using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, _iters))
                    mask = kdf.GetBytes(81);

                byte[] iv  = new byte[16];
                byte[] key = new byte[32];
                for (int i = 0; i < 16; i++) iv[i]  = (byte)(scrambledIv[i]  ^ mask[i]);
                for (int i = 0; i < 32; i++) key[i] = (byte)(scrambledKey[i] ^ mask[16 + i]);
                byte xorSeed = (byte)(wrappedXor ^ mask[48]);

                byte[] hmacKey = new byte[32];
                Buffer.BlockCopy(mask, 49, hmacKey, 0, 32);
                byte[] computedMac;
                using (HMACSHA256 vh = new HMACSHA256(hmacKey))
                    computedMac = vh.ComputeHash(enc);
                int diff = 0;
                for (int i = 0; i < 32; i++) diff |= storedMac[i] ^ computedMac[i];
                Array.Clear(hmacKey, 0, hmacKey.Length);
                Array.Clear(computedMac, 0, computedMac.Length);
                Array.Clear(storedMac, 0, storedMac.Length);
                if (diff != 0)
                    throw new CryptographicException();

                Array.Clear(password, 0, password.Length);
                Array.Clear(mask,     0, mask.Length);
                Array.Clear(salt,     0, salt.Length);
                Array.Clear(scrambledIv,  0, scrambledIv.Length);
                Array.Clear(scrambledKey, 0, scrambledKey.Length);

                for (int i = 0; i < enc.Length; i++)
                    enc[i] ^= (byte)(xorSeed ^ (i & 0xFF));

                byte[] aesOut;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform dec = aes.CreateDecryptor())
                        aesOut = dec.TransformFinalBlock(enc, 0, enc.Length);
                }
                Array.Clear(key, 0, key.Length);
                Array.Clear(iv,  0, iv.Length);
                Array.Clear(enc, 0, enc.Length);

                byte[] plain;
                using (MemoryStream ms = new MemoryStream(aesOut))
                using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Decompress))
                using (MemoryStream outMs = new MemoryStream())
                {
                    ds.CopyTo(outMs);
                    plain = outMs.ToArray();
                }
                Array.Clear(aesOut, 0, aesOut.Length);

                int p = 0;
                int n = ReadInt32(plain, p); p += 4;
                int[]  ofs = new int[n];
                for (int i = 0; i < n; i++)
                {
                    ofs[i] = ReadInt32(plain, p); p += 4;
                }
                _entryOff = ofs;
                _blob     = plain;

                WipeSensitiveState();
            }
        }

        private static object FakeReturnForHandle(RuntimeMethodHandle handle)
        {
            try
            {
                MethodBase mb = MethodBase.GetMethodFromHandle(handle);
                MethodInfo mi = mb as MethodInfo;
                Type rt = mi != null ? mi.ReturnType : typeof(void);
                if (rt == typeof(void)) return null;
                if (rt == typeof(bool)) return false;
                if (rt == typeof(string)) return "";
                if (rt.IsArray)
                {
                    try { return Array.CreateInstance(rt.GetElementType(), 0); }
                    catch { return null; }
                }
                if (rt.IsValueType)
                {

                    try { return Activator.CreateInstance(rt); }
                    catch { return null; }
                }

                return null;
            }
            catch { return null; }
        }

        private static void WipeSensitiveState()
        {
            try
            {
                if (_pepper != null)
                {
                    Array.Clear(_pepper, 0, _pepper.Length);
                    _pepper = new byte[0];
                }
                _iters  = 0;
                _resName = "";
            }
            catch { }
        }

        private static int ReadInt32(byte[] b, int o)
        {
            return (b[o]) | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
        }

        private static void WriteInt32(byte[] b, int o, int v)
        {
            b[o]     = (byte)(v       & 0xFF);
            b[o + 1] = (byte)((v >> 8) & 0xFF);
            b[o + 2] = (byte)((v >> 16) & 0xFF);
            b[o + 3] = (byte)((v >> 24) & 0xFF);
        }
    }
}

