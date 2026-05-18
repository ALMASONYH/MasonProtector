using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class ResourceVaultProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal ResourceVaultProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal bool Apply(ModuleDef module, TypeDef modType, string companionName, string outputExePath)
        {
            if (string.IsNullOrEmpty(companionName)) return false;
            if (module == null) return false;
            string sanitized = Sanitize(companionName);

            List<VaultEntry> vaultEntries = new List<VaultEntry>();
            List<Resource> toRemove = new List<Resource>();
            HashSet<string> seenNames = new HashSet<string>(StringComparer.Ordinal);

            foreach (Resource res in module.Resources)
            {
                EmbeddedResource er = res as EmbeddedResource;
                if (er == null) continue;
                if (string.IsNullOrEmpty(er.Name)) continue;
                if (!engine.injectedResources.Contains(er.Name)) continue;
                if (seenNames.Contains(er.Name)) continue;

                byte[] data;
                try
                {
                    using (Stream rdr = er.CreateReader().AsStream())
                    using (MemoryStream ms = new MemoryStream())
                    {
                        rdr.CopyTo(ms);
                        data = ms.ToArray();
                    }
                }
                catch { continue; }
                if (data == null || data.Length == 0) continue;

                VaultEntry ve = new VaultEntry();
                ve.Name = er.Name;
                ve.Plain = data;
                ve.IsDecoy = false;
                vaultEntries.Add(ve);
                seenNames.Add(er.Name);
                toRemove.Add(res);
            }

            if (vaultEntries.Count == 0) return false;

            foreach (Resource r in toRemove)
                module.Resources.Remove(r);

            int decoyCount = rng.Next(6, 14);
            for (int i = 0; i < decoyCount; i++)
            {
                string decoyName = BuildDecoyName(seenNames);
                int decoySize = rng.Next(64, 4096);
                VaultEntry decoy = new VaultEntry();
                decoy.Name = decoyName;
                decoy.Plain = engine.CryptoRandom(decoySize);
                decoy.IsDecoy = true;
                vaultEntries.Add(decoy);
                seenNames.Add(decoyName);
            }

            Shuffle(vaultEntries);

            byte[] ctrlKey  = engine.CryptoRandom(32);
            byte[] ctrlIv   = engine.CryptoRandom(16);
            byte[] indexKey = engine.CryptoRandom(32);
            byte[] indexIv  = engine.CryptoRandom(16);
            byte[] dataMaster = engine.CryptoRandom(48);
            byte[] tag = engine.CryptoRandom(16);
            byte[] hmacKey = engine.CryptoRandom(32);

            const int seedLen = 176;
            byte[] seedRaw = new byte[seedLen];
            Buffer.BlockCopy(ctrlKey,    0, seedRaw, 0,   32);
            Buffer.BlockCopy(ctrlIv,     0, seedRaw, 32,  16);
            Buffer.BlockCopy(indexKey,   0, seedRaw, 48,  32);
            Buffer.BlockCopy(indexIv,    0, seedRaw, 80,  16);
            Buffer.BlockCopy(dataMaster, 0, seedRaw, 96,  48);
            Buffer.BlockCopy(hmacKey,    0, seedRaw, 144, 32);

            byte[] mask1 = engine.CryptoRandom(seedLen);
            byte[] mask2 = engine.CryptoRandom(seedLen);
            byte[] offsets = engine.CryptoRandom(32);

            byte[] seedScrambled = new byte[seedLen];
            for (int i = 0; i < seedLen; i++)
            {
                int o1 = (i + offsets[i & 0x1F]) % seedLen;
                int o2 = (i + offsets[(i + 7) & 0x1F]) % seedLen;
                seedScrambled[i] = (byte)(seedRaw[i] ^ mask1[o1] ^ mask2[o2]);
            }

            byte[] magic = engine.CryptoRandom(4);
            byte[] companionBytes = BuildCompanion(vaultEntries,
                ctrlKey, ctrlIv, indexKey, indexIv, dataMaster, hmacKey, tag, magic);

            string outputDir = Path.GetDirectoryName(outputExePath);
            if (string.IsNullOrEmpty(outputDir)) outputDir = ".";
            string companionPath = Path.Combine(outputDir, sanitized + ".dll");

            try
            {
                File.WriteAllBytes(companionPath, companionBytes);
            }
            catch
            {
                return false;
            }

            TypeDef helper = CloneRuntime(module);
            if (helper == null)
            {
                try { File.Delete(companionPath); } catch { }
                return false;
            }

            FieldDef fFile    = helper.FindField("_file");
            FieldDef fSeed    = helper.FindField("_seed");
            FieldDef fMask1   = helper.FindField("_mask1");
            FieldDef fMask2   = helper.FindField("_mask2");
            FieldDef fOff     = helper.FindField("_off");
            FieldDef fTag     = helper.FindField("_tag");
            FieldDef fMagic   = helper.FindField("_magic");
            FieldDef fLock    = helper.FindField("_lock");
            MethodDef mGetStream = helper.FindMethod("GetStream");

            if (fFile == null || fSeed == null || fMask1 == null || fMask2 == null ||
                fOff == null || fTag == null || fMagic == null || fLock == null || mGetStream == null)
            {
                try { File.Delete(companionPath); } catch { }
                return false;
            }

            foreach (MethodDef hm in helper.Methods)
            {
                if (hm.IsConstructor || hm.IsStaticConstructor) continue;
                hm.Name = engine.MakeName();
            }
            foreach (FieldDef hf in helper.Fields)
            {
                hf.Name = engine.MakeName();
            }

            BuildCctor(module, helper, fFile, fSeed, fMask1, fMask2, fOff, fTag, fMagic, fLock,
                sanitized, seedScrambled, mask1, mask2, offsets, tag, magic);

            PatchResourceAccessCalls(module, mGetStream);

            Array.Clear(ctrlKey,    0, ctrlKey.Length);
            Array.Clear(ctrlIv,     0, ctrlIv.Length);
            Array.Clear(indexKey,   0, indexKey.Length);
            Array.Clear(indexIv,    0, indexIv.Length);
            Array.Clear(dataMaster, 0, dataMaster.Length);
            Array.Clear(hmacKey,    0, hmacKey.Length);
            Array.Clear(seedRaw,    0, seedRaw.Length);

            return true;
        }

        private string Sanitize(string name)
        {
            if (string.IsNullOrEmpty(name)) return MakeNeutralFallback();
            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder sb = new StringBuilder(name.Length);
            foreach (char c in name)
                if (Array.IndexOf(invalid, c) < 0) sb.Append(c);
            string s = sb.ToString();
            if (s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(0, s.Length - 4);
            if (string.IsNullOrEmpty(s)) s = MakeNeutralFallback();
            return s;
        }

        private string MakeNeutralFallback()
        {
            string[] neutral = new string[] {
                "Resources", "Properties", "Internal", "Core", "Common",
                "Shared", "Runtime", "Engine", "Service", "Platform"
            };
            return neutral[rng.Next(neutral.Length)];
        }

        private string BuildDecoyName(HashSet<string> taken)
        {
            string[] motifs = new string[] {
                "Resources", "Properties", "Strings", "Settings", "Data", "Assets",
                "Config", "Texts", "Cache", "Metadata", "Internal", "Common", "Core"
            };
            string[] suffixes = new string[] { ".resources", ".bin", ".dat", ".cache", "" };
            for (int attempt = 0; attempt < 32; attempt++)
            {
                StringBuilder sb = new StringBuilder();
                int parts = rng.Next(1, 4);
                for (int p = 0; p < parts; p++)
                {
                    if (p > 0) sb.Append('.');
                    sb.Append(motifs[rng.Next(motifs.Length)]);
                }
                sb.Append('_');
                int extra = rng.Next(4, 9);
                for (int x = 0; x < extra; x++)
                {
                    int r = rng.Next(36);
                    sb.Append((char)(r < 10 ? '0' + r : 'a' + (r - 10)));
                }
                sb.Append(suffixes[rng.Next(suffixes.Length)]);
                string s = sb.ToString();
                if (!taken.Contains(s)) return s;
            }
            return "$_decoy_" + Guid.NewGuid().ToString("N");
        }

        private void Shuffle(List<VaultEntry> list)
        {
            for (int i = list.Count - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                VaultEntry tmp = list[i];
                list[i] = list[j];
                list[j] = tmp;
            }
        }

        private class VaultEntry
        {
            public string Name;
            public byte[] Plain;
            public bool IsDecoy;
            public byte[] Cipher;
            public byte[] IvSeg;
            public byte[] KeyMask;
            public byte[] Hmac;
            public int DataOffsetRel;
        }

        private byte[] BuildCompanion(List<VaultEntry> entries,
            byte[] ctrlKey, byte[] ctrlIv,
            byte[] indexKey, byte[] indexIv,
            byte[] dataMaster, byte[] hmacKey, byte[] tag, byte[] magic)
        {
            int count = entries.Count;

            List<byte[]> dataChunks = new List<byte[]>(count * 2 + 1);
            int dataCursor = 0;

            byte[] leadJunk = engine.CryptoRandom(rng.Next(8, 96));
            dataChunks.Add(leadJunk);
            dataCursor += leadJunk.Length;

            for (int i = 0; i < count; i++)
            {
                VaultEntry e = entries[i];

                byte[] compressed;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Compress, true))
                        ds.Write(e.Plain, 0, e.Plain.Length);
                    compressed = ms.ToArray();
                }

                byte[] segHmac;
                using (HMACSHA256 h = new HMACSHA256(hmacKey))
                    segHmac = h.ComputeHash(compressed);

                byte[] segIv      = engine.CryptoRandom(16);
                byte[] segKeyMask = engine.CryptoRandom(32);
                byte[] segKey     = DeriveSegmentKey(dataMaster, tag, e.Name, i);
                for (int k = 0; k < 32; k++) segKey[k] ^= segKeyMask[k];

                byte[] segCipher = AesEnc(compressed, segKey, segIv);
                Array.Clear(segKey, 0, segKey.Length);

                byte[] segStream = SeededStream(tag, (byte)(0x91 ^ (i & 0x7F)), segCipher.Length);
                for (int k = 0; k < segCipher.Length; k++) segCipher[k] ^= segStream[k];

                e.Cipher = segCipher;
                e.IvSeg = segIv;
                e.KeyMask = segKeyMask;
                e.Hmac = segHmac;

                int junkBefore = rng.Next(4, 80);
                byte[] junk = engine.CryptoRandom(junkBefore);
                dataChunks.Add(junk);
                dataCursor += junkBefore;
                e.DataOffsetRel = dataCursor;
                dataChunks.Add(segCipher);
                dataCursor += segCipher.Length;
            }

            byte[] indexPlain;
            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < count; i++)
                {
                    VaultEntry e = entries[i];
                    byte[] nameBytes = Encoding.UTF8.GetBytes(e.Name);
                    if (nameBytes.Length > 4096) throw new InvalidOperationException();
                    ms.WriteByte((byte)(nameBytes.Length & 0xFF));
                    ms.WriteByte((byte)((nameBytes.Length >> 8) & 0xFF));
                    ms.Write(nameBytes, 0, nameBytes.Length);
                    ms.WriteByte(e.IsDecoy ? (byte)0 : (byte)1);
                    WriteInt(ms, e.DataOffsetRel);
                    WriteInt(ms, e.Cipher.Length);
                    ms.Write(e.IvSeg, 0, 16);
                    ms.Write(e.KeyMask, 0, 32);
                    ms.Write(e.Hmac, 0, 32);
                }
                indexPlain = ms.ToArray();
            }

            byte[] indexCipher = AesEnc(indexPlain, indexKey, indexIv);
            byte[] indexMix = SeededStream(tag, 0x53, indexCipher.Length);
            for (int i = 0; i < indexCipher.Length; i++) indexCipher[i] ^= indexMix[i];

            int idxOff = 128;
            int idxLen = indexCipher.Length;
            int junkAfterIndex = rng.Next(48, 384);
            int dataOff = idxOff + idxLen + junkAfterIndex;

            byte[] ctrlPlain = new byte[64];
            ctrlPlain[0] = magic[0]; ctrlPlain[1] = magic[1]; ctrlPlain[2] = magic[2]; ctrlPlain[3] = magic[3];
            WriteIntAt(ctrlPlain, 4,  count);
            WriteIntAt(ctrlPlain, 8,  idxOff);
            WriteIntAt(ctrlPlain, 12, idxLen);
            WriteIntAt(ctrlPlain, 16, dataOff);
            byte[] padRand = engine.CryptoRandom(44);
            Buffer.BlockCopy(padRand, 0, ctrlPlain, 20, 44);

            byte[] ctrlCipher = AesEncNoPad(ctrlPlain, ctrlKey, ctrlIv);
            byte[] ctrlMix = SeededStream(tag, 0x41, 64);
            for (int i = 0; i < 64; i++) ctrlCipher[i] ^= ctrlMix[i];

            int totalLength = dataOff;
            foreach (byte[] c in dataChunks) totalLength += c.Length;

            byte[] header = BuildFakeHeader();

            byte[] file = new byte[totalLength];
            Buffer.BlockCopy(header, 0, file, 0, 64);
            Buffer.BlockCopy(ctrlCipher, 0, file, 64, 64);
            Buffer.BlockCopy(indexCipher, 0, file, idxOff, idxLen);
            byte[] gap = engine.CryptoRandom(junkAfterIndex);
            Buffer.BlockCopy(gap, 0, file, idxOff + idxLen, junkAfterIndex);

            int cursor = dataOff;
            foreach (byte[] chunk in dataChunks)
            {
                Buffer.BlockCopy(chunk, 0, file, cursor, chunk.Length);
                cursor += chunk.Length;
            }

            return file;
        }

        private byte[] DeriveSegmentKey(byte[] dataMaster, byte[] tag, string entryName, int idx)
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

        private byte[] BuildFakeHeader()
        {
            byte[] h = engine.CryptoRandom(64);
            h[0] = (byte)'M';
            h[1] = (byte)'Z';
            h[2] = 0x90;
            h[3] = 0x00;
            h[60] = 0x80;
            h[61] = 0x00;
            h[62] = 0x00;
            h[63] = 0x00;
            return h;
        }

        private static byte[] AesEnc(byte[] plain, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Key = key;
                aes.IV = iv;
                using (ICryptoTransform enc = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                {
                    cs.Write(plain, 0, plain.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        private static byte[] AesEncNoPad(byte[] plain, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Key = key;
                aes.IV = iv;
                using (ICryptoTransform enc = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                {
                    cs.Write(plain, 0, plain.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
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

        private static void WriteInt(MemoryStream ms, int v)
        {
            ms.WriteByte((byte)(v & 0xFF));
            ms.WriteByte((byte)((v >> 8) & 0xFF));
            ms.WriteByte((byte)((v >> 16) & 0xFF));
            ms.WriteByte((byte)((v >> 24) & 0xFF));
        }

        private static void WriteIntAt(byte[] buf, int off, int v)
        {
            buf[off]     = (byte)(v & 0xFF);
            buf[off + 1] = (byte)((v >> 8) & 0xFF);
            buf[off + 2] = (byte)((v >> 16) & 0xFF);
            buf[off + 3] = (byte)((v >> 24) & 0xFF);
        }

        private TypeDef CloneRuntime(ModuleDef userModule)
        {
            string protectorPath = typeof(ResourceVaultProtection).Assembly.Location;
            ModuleDefMD srcModule;
            try
            {
                srcModule = ModuleDefMD.Load(protectorPath);
            }
            catch
            {
                return null;
            }

            TypeDef srcHelper = srcModule.Find(
                "MasonProtector.Core.RuntimeStubs.ResourceVaultRuntime", false);
            if (srcHelper == null) return null;

            TypeCloner cloner = new TypeCloner(srcModule, userModule);
            string helperName = engine.MakeName();
            TypeDef dstHelper = cloner.CloneType(srcHelper, "", helperName);
            engine.injectedTypes.Add(dstHelper);
            foreach (MethodDef dm in dstHelper.Methods) engine.injectedMethods.Add(dm);
            return dstHelper;
        }

        private void BuildCctor(ModuleDef module, TypeDef helper,
            FieldDef fFile, FieldDef fSeed, FieldDef fMask1, FieldDef fMask2,
            FieldDef fOff, FieldDef fTag, FieldDef fMagic, FieldDef fLock,
            string fileName, byte[] seedScrambled, byte[] mask1, byte[] mask2,
            byte[] offsets, byte[] tag, byte[] magic)
        {
            MethodDef cctor = helper.FindStaticConstructor();
            if (cctor == null)
            {
                cctor = new MethodDefUser(".cctor",
                    MethodSig.CreateStatic(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                    DnMethodAttributes.RTSpecialName);
                helper.Methods.Add(cctor);
                engine.injectedMethods.Add(cctor);
            }

            cctor.Body = new CilBody();
            cctor.Body.InitLocals = true;
            cctor.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            cctor.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            IList<Instruction> il = cctor.Body.Instructions;

            MemberRefUser objCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                module.CorLibTypes.Object.TypeDefOrRef);
            il.Add(Instruction.Create(DnOpCodes.Newobj, objCtor));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fLock));

            EmitObfuscatedStringStore(module, helper, il, fFile, fileName);

            EmitRvaByteArray(module, helper, il, fSeed,  seedScrambled);
            EmitRvaByteArray(module, helper, il, fMask1, mask1);
            EmitRvaByteArray(module, helper, il, fMask2, mask2);
            EmitRvaByteArray(module, helper, il, fOff,   offsets);
            EmitRvaByteArray(module, helper, il, fTag,   tag);
            EmitRvaByteArray(module, helper, il, fMagic, magic);

            il.Add(Instruction.Create(DnOpCodes.Ret));
            cctor.Body.KeepOldMaxStack = false;
        }

        private void EmitObfuscatedStringStore(ModuleDef module, TypeDef helper,
            IList<Instruction> il, FieldDef targetStringField, string text)
        {
            byte[] plain = Encoding.UTF8.GetBytes(text);
            byte[] key = engine.CryptoRandom(Math.Max(7, plain.Length / 2 + 1));
            byte[] cipher = new byte[plain.Length];
            for (int i = 0; i < plain.Length; i++)
                cipher[i] = (byte)(plain[i] ^ key[i % key.Length] ^ (byte)(i * 0x57));

            FieldDef fCipher = CreateRvaByteField(module, helper, cipher);
            FieldDef fKey = CreateRvaByteField(module, helper, key);

            Importer importer = new Importer(module);
            ITypeDefOrRef sysByte = importer.Import(typeof(byte));
            IMethod rhInitArr = importer.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers)
                .GetMethod("InitializeArray",
                    new Type[] { typeof(Array), typeof(RuntimeFieldHandle) }));
            IMethod utf8Get = importer.Import(typeof(Encoding).GetProperty("UTF8").GetGetMethod());
            IMethod utf8GetString = importer.Import(typeof(Encoding).GetMethod("GetString", new Type[] { typeof(byte[]) }));

            il.Add(engine.LoadInt(cipher.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, sysByte));
            il.Add(Instruction.Create(DnOpCodes.Dup));
            il.Add(Instruction.Create(DnOpCodes.Ldtoken, fCipher));
            il.Add(Instruction.Create(DnOpCodes.Call, rhInitArr));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(engine.LoadInt(key.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, sysByte));
            il.Add(Instruction.Create(DnOpCodes.Dup));
            il.Add(Instruction.Create(DnOpCodes.Ldtoken, fKey));
            il.Add(Instruction.Create(DnOpCodes.Call, rhInitArr));
            FieldDef fKeyHolder = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            helper.Fields.Add(fKeyHolder);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fKeyHolder));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            Instruction loopCond = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Br, loopCond));

            Instruction loopBody = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, fKeyHolder));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, fKeyHolder));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Rem));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0x57));
            il.Add(Instruction.Create(DnOpCodes.Mul));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Conv_U1));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(loopCond);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Call, utf8Get));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, utf8GetString));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, targetStringField));
        }

        private FieldDef CreateRvaByteField(ModuleDef module, TypeDef helper, byte[] bytes)
        {
            Importer importer = new Importer(module);
            ITypeDefOrRef sysValueType = importer.Import(typeof(ValueType));

            string holderName = engine.MakeName();
            TypeDef holder = new TypeDefUser("", holderName, sysValueType);
            holder.Attributes = DnTypeAttributes.NestedPrivate
                              | DnTypeAttributes.SequentialLayout
                              | DnTypeAttributes.Sealed;
            holder.ClassLayout = new ClassLayoutUser(1, (uint)bytes.Length);
            helper.NestedTypes.Add(holder);
            engine.injectedTypes.Add(holder);

            FieldDef rvaField = new FieldDefUser(engine.MakeName(),
                new FieldSig(holder.ToTypeSig()),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static
                | DnFieldAttributes.HasFieldRVA);
            rvaField.HasFieldRVA = true;
            rvaField.InitialValue = (byte[])bytes.Clone();
            helper.Fields.Add(rvaField);
            return rvaField;
        }

        private void EmitRvaByteArray(ModuleDef module, TypeDef helper,
            IList<Instruction> il, FieldDef target, byte[] bytes)
        {
            Importer importer = new Importer(module);
            ITypeDefOrRef sysValueType = importer.Import(typeof(ValueType));
            ITypeDefOrRef sysByte = importer.Import(typeof(byte));
            IMethod rhInitArr = importer.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers)
                .GetMethod("InitializeArray",
                    new Type[] { typeof(Array), typeof(RuntimeFieldHandle) }));

            string holderName = engine.MakeName();
            TypeDef holder = new TypeDefUser("", holderName, sysValueType);
            holder.Attributes = DnTypeAttributes.NestedPrivate
                              | DnTypeAttributes.SequentialLayout
                              | DnTypeAttributes.Sealed;
            holder.ClassLayout = new ClassLayoutUser(1, (uint)bytes.Length);
            helper.NestedTypes.Add(holder);
            engine.injectedTypes.Add(holder);

            FieldDef rvaField = new FieldDefUser(engine.MakeName(),
                new FieldSig(holder.ToTypeSig()),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static
                | DnFieldAttributes.HasFieldRVA);
            rvaField.HasFieldRVA = true;
            rvaField.InitialValue = (byte[])bytes.Clone();
            helper.Fields.Add(rvaField);

            il.Add(engine.LoadInt(bytes.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, sysByte));
            il.Add(Instruction.Create(DnOpCodes.Dup));
            il.Add(Instruction.Create(DnOpCodes.Ldtoken, rvaField));
            il.Add(Instruction.Create(DnOpCodes.Call, rhInitArr));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, target));
        }

        private void PatchResourceAccessCalls(ModuleDef module, MethodDef getStreamMethod)
        {
            TypeDef helperType = getStreamMethod.DeclaringType;
            int patched = 0;
            foreach (TypeDef t in module.GetTypes())
            {
                if (t == helperType) continue;

                if (engine.IsTypeUserExcluded(t)) continue;
                foreach (MethodDef m in t.Methods)
                {
                    if (m == null || m.Body == null || !m.Body.HasInstructions) continue;
                    if (m == getStreamMethod) continue;
                    if (engine.IsMethodUserExcluded(m)) continue;

                    IList<Instruction> instr = m.Body.Instructions;
                    for (int i = 0; i < instr.Count; i++)
                    {
                        Instruction inst = instr[i];
                        if (inst.OpCode != DnOpCodes.Callvirt && inst.OpCode != DnOpCodes.Call) continue;

                        IMethod op = inst.Operand as IMethod;
                        if (op == null) continue;
                        if (op.Name != "GetManifestResourceStream") continue;

                        ITypeDefOrRef decl = op.DeclaringType;
                        if (decl == null) continue;
                        if (decl.FullName != "System.Reflection.Assembly") continue;

                        MethodSig sig = op.MethodSig;
                        if (sig == null || sig.Params == null || sig.Params.Count != 1) continue;
                        if (sig.Params[0].FullName != "System.String") continue;

                        inst.OpCode = DnOpCodes.Call;
                        inst.Operand = getStreamMethod;
                        patched++;
                    }
                }
            }
        }
    }
}

