using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class StringEncryptionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int VAULT_COUNT = 16;
        private const int VAULT_SIZE = 512;
        private const int DECRYPTOR_COUNT = 16;
        private const int FAKE_DECOY_COUNT = 16;
        private const int RESOLVER_VARIANTS = 6;
        private const int INVERTIBLE_RESOLVER_VARIANTS = 6;
        private const int CIPHER_MODES = 6;
        private List<FieldDef> vaults;
        private List<int[]> vaultData;
        private List<int[]> vaultShuffle;
        private int[] vaultAllocPtr;
        private List<List<MethodDef>> vaultResolvers;
        private List<TypeDef> vaultHosts;
        private List<MethodDefUser> strDecryptors;

        internal StringEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyStringEncryption(ModuleDef module, TypeDef modType)
        {
            BuildVaultInfrastructure(module, modType);

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    try
                    {
                        EncryptMethodStrings(module, modType, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            foreach (TypeDef cgType in module.GetTypes())
            {
                if (!IsEncryptableCompilerGeneratedType(cgType)) continue;
                foreach (MethodDef method in cgType.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    try
                    {
                        EncryptMethodStrings(module, modType, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                if (engine.injectedTypes.Contains(type)) continue;
                if (!type.HasGenericParameters) continue;
                if (engine.IsWinFormsType(type)) continue;

                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (method.Name == "InitializeComponent") continue;

                    if (engine.IsMethodUserExcluded(method)) continue;
                    try
                    {
                        EncryptMethodStrings(module, modType, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            var initMethod = BuildVaultInitializer(module);
            modType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);
            engine.InjectCallInCctor(module, modType, initMethod);
        }

        internal void ApplyLateStringEncryption(ModuleDef module, TypeDef modType)
        {
            var methodsToEncrypt = engine.injectedMethods.ToList();

            BuildVaultInfrastructure(module, modType);

            foreach (MethodDef method in methodsToEncrypt)
            {
                if (!method.HasBody || !method.Body.HasInstructions) continue;

                if (method.DeclaringType != null &&
                    engine.lateStringEncryptionExcludedTypes.Contains(method.DeclaringType))
                    continue;
                try { EncryptMethodStrings(module, modType, method); } catch { }
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(type)) continue;
                if (!engine.IsWinFormsType(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (method.Name == "InitializeComponent") continue;
                    if (engine.IsMethodUserExcluded(method)) continue;
                    try { EncryptMethodStrings(module, modType, method); } catch { }
                }
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (method.Name != "InitializeComponent") continue;
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.IsMethodUserExcluded(method)) continue;
                    try
                    {
                        EncryptMethodStrings(module, modType, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            var initMethod = BuildVaultInitializer(module);
            modType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);
            engine.InjectCallAtTop(module, modType, initMethod);
        }

        private void BuildVaultInfrastructure(ModuleDef module, TypeDef modType)
        {
            vaults = new List<FieldDef>();
            vaultData = new List<int[]>();
            vaultShuffle = new List<int[]>();
            vaultAllocPtr = new int[VAULT_COUNT];
            vaultResolvers = new List<List<MethodDef>>();
            vaultHosts = new List<TypeDef>();

            for (int v = 0; v < VAULT_COUNT; v++)
            {
                TypeDef host;
                if (v == 0)
                {
                    host = modType;
                }
                else
                {
                    host = new TypeDefUser("", engine.MakeName(),
                        module.CorLibTypes.Object.TypeDefOrRef);
                    host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                        DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                    module.Types.Add(host);
                    engine.injectedTypes.Add(host);

                    for (int d = 0; d < rng.Next(3, 8); d++)
                    {
                        host.Fields.Add(new FieldDefUser(engine.MakeName(),
                            new FieldSig(module.CorLibTypes.Int32),
                            DnFieldAttributes.Private | DnFieldAttributes.Static));
                    }
                }
                vaultHosts.Add(host);

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                vaults.Add(field);

                var data = new int[VAULT_SIZE];
                for (int i = 0; i < VAULT_SIZE; i++)
                    data[i] = rng.Next(int.MinValue, int.MaxValue);
                vaultData.Add(data);

                var shuffle = new int[VAULT_SIZE];
                for (int i = 0; i < VAULT_SIZE; i++) shuffle[i] = i;
                for (int i = VAULT_SIZE - 1; i > 0; i--)
                {
                    int j = rng.Next(0, i + 1);
                    int t = shuffle[i]; shuffle[i] = shuffle[j]; shuffle[j] = t;
                }
                vaultShuffle.Add(shuffle);
                vaultAllocPtr[v] = 0;

                var resolvers = new List<MethodDef>();
                for (int r = 0; r < RESOLVER_VARIANTS; r++)
                {
                    var resolver = BuildVaultResolver(module, field, engine.MakeName(), r);
                    host.Methods.Add(resolver);
                    engine.injectedMethods.Add(resolver);
                    resolvers.Add(resolver);
                }

                for (int r = 0; r < 4; r++)
                {
                    var decoy = BuildVaultResolver(module, field, engine.MakeName(), rng.Next(0, RESOLVER_VARIANTS));
                    host.Methods.Add(decoy);
                    engine.injectedMethods.Add(decoy);
                }
                vaultResolvers.Add(resolvers);
            }

            strDecryptors = new List<MethodDefUser>();
            for (int m = 0; m < DECRYPTOR_COUNT; m++)
            {
                var targetHost = vaultHosts[(m + 1) % VAULT_COUNT];
                var decr = BuildDecryptor(module, engine.MakeName(), m);
                targetHost.Methods.Add(decr);
                engine.injectedMethods.Add(decr);
                strDecryptors.Add(decr);
            }

            for (int f = 0; f < FAKE_DECOY_COUNT; f++)
            {
                var fakeHost = vaultHosts[rng.Next(0, VAULT_COUNT)];
                var fake = BuildFakeDecryptor(module, engine.MakeName());
                fakeHost.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }
        }

        private bool IsEncryptableCompilerGeneratedType(TypeDef type)
        {
            if (type == null) return false;
            if (engine.injectedTypes.Contains(type)) return false;
            if (type.IsGlobalModuleType || type.Name == "<Module>") return false;
            if (type.Name.StartsWith("<PrivateImplementationDetails>")) return false;
            if (type.Name.StartsWith("__StaticArrayInit")) return false;
            return engine.IsCompilerGenerated(type);
        }

        private int AllocVaultSlot(int vaultIdx)
        {
            if (vaultAllocPtr[vaultIdx] >= VAULT_SIZE) return -1;
            return vaultShuffle[vaultIdx][vaultAllocPtr[vaultIdx]++];
        }

        private void EncryptMethodStrings(ModuleDef module, TypeDef modType, MethodDef method)
        {
            var il = method.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode != DnOpCodes.Ldstr) continue;
                string orig = il[i].Operand as string;

                if (string.IsNullOrEmpty(orig) || orig.Length > 65535) continue;

                int mode = rng.Next(0, CIPHER_MODES);

                byte[] cryptoBytes = engine.CryptoRandom(2);
                int key1 = 1 + (cryptoBytes[0] % 254);
                int key2 = 1 + (cryptoBytes[1] % 254);
                while (key2 == key1)
                {
                    byte[] retry = engine.CryptoRandom(1);
                    key2 = 1 + (retry[0] % 254);
                }

                string encrypted = EncStr(orig, key1, key2, mode);
                int splitPos = rng.Next(1, Math.Max(2, encrypted.Length));
                string partA = encrypted.Substring(0, splitPos);
                string partB = encrypted.Substring(splitPos);
                int combo = (key1 << 16) | (key2 << 8) | mode;

                var keyInsts = BuildKeyRetrieval(combo);

                int decryptorIdx = mode;
                int copyCount = strDecryptors.Count / CIPHER_MODES;
                if (copyCount > 1)
                    decryptorIdx = mode + CIPHER_MODES * rng.Next(0, copyCount);
                if (decryptorIdx >= strDecryptors.Count) decryptorIdx = mode;

                il[i].Operand = partA;
                il.Insert(i + 1, Instruction.Create(DnOpCodes.Ldstr, partB));
                int idx = i + 2;
                foreach (var inst in keyInsts)
                    il.Insert(idx++, inst);
                il.Insert(idx, Instruction.Create(DnOpCodes.Call, strDecryptors[decryptorIdx]));
                i = idx;
            }
        }

        private string EncStr(string input, int k1, int k2, int mode)
        {
            char[] enc = new char[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                int ch = input[i];
                switch (mode % CIPHER_MODES)
                {
                    case 0: ch ^= k1 ^ (i * k2); break;
                    case 1: ch ^= (k1 + i) ^ k2; break;
                    case 2: ch ^= k1 ^ k2 ^ (i + 1); break;
                    case 3: ch = ((ch + k2 - i) ^ k1); break;
                    case 4: ch ^= (k1 * (i + 1)) ^ k2; break;
                    default: ch ^= k1 ^ (k2 << (i % 8)); break;
                }
                enc[i] = (char)(ch & 0xFFFF);
            }
            return new string(enc);
        }

        private List<Instruction> BuildKeyRetrieval(int target)
        {
            int pattern = rng.Next(0, 6);
            switch (pattern)
            {
                case 0: return BuildSameVaultRetrieval(target);
                case 1: return BuildCrossVaultRetrieval(target);
                case 2: return BuildTripleVaultRetrieval(target);
                case 3: return BuildQuadVaultRetrieval(target);
                case 4: return BuildMixedVaultRetrieval(target);
                default: return BuildMathRetrieval(target);
            }
        }

        private List<Instruction> BuildSameVaultRetrieval(int target)
        {
            int v = rng.Next(0, VAULT_COUNT);
            int s1 = AllocVaultSlot(v);
            int s2 = AllocVaultSlot(v);
            if (s1 < 0 || s2 < 0) return BuildMathRetrieval(target);

            int rt = rng.Next(0, RESOLVER_VARIANTS);
            SetVaultPair(v, s1, s2, target, rt);

            var insts = new List<Instruction>();
            insts.AddRange(BuildIdxPuzzle(s1));
            insts.AddRange(BuildIdxPuzzle(s2));
            insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[v][rt]));
            return insts;
        }

        private List<Instruction> BuildCrossVaultRetrieval(int target)
        {
            int vA = rng.Next(0, VAULT_COUNT);
            int vB = rng.Next(0, VAULT_COUNT);
            while (vB == vA) vB = rng.Next(0, VAULT_COUNT);

            int a1 = AllocVaultSlot(vA), a2 = AllocVaultSlot(vA);
            int b1 = AllocVaultSlot(vB), b2 = AllocVaultSlot(vB);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0) return BuildMathRetrieval(target);

            int partial = rng.Next(int.MinValue, int.MaxValue);
            int other = partial ^ target;

            int rtA = rng.Next(0, RESOLVER_VARIANTS);
            int rtB = rng.Next(0, RESOLVER_VARIANTS);
            SetVaultPair(vA, a1, a2, partial, rtA);
            SetVaultPair(vB, b1, b2, other, rtB);

            var insts = new List<Instruction>();
            insts.AddRange(BuildIdxPuzzle(a1));
            insts.AddRange(BuildIdxPuzzle(a2));
            insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[vA][rtA]));
            insts.AddRange(BuildIdxPuzzle(b1));
            insts.AddRange(BuildIdxPuzzle(b2));
            insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[vB][rtB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildTripleVaultRetrieval(int target)
        {
            int vA = rng.Next(0, VAULT_COUNT);
            int vB = rng.Next(0, VAULT_COUNT);
            while (vB == vA) vB = rng.Next(0, VAULT_COUNT);
            int vC = rng.Next(0, VAULT_COUNT);
            while (vC == vA || vC == vB) vC = rng.Next(0, VAULT_COUNT);

            int a1 = AllocVaultSlot(vA), a2 = AllocVaultSlot(vA);
            int b1 = AllocVaultSlot(vB), b2 = AllocVaultSlot(vB);
            int c1 = AllocVaultSlot(vC), c2 = AllocVaultSlot(vC);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0 || c1 < 0 || c2 < 0)
                return BuildMathRetrieval(target);

            int p1 = rng.Next(int.MinValue, int.MaxValue);
            int p2 = rng.Next(int.MinValue, int.MaxValue);
            int p3 = target ^ p1 ^ p2;

            int rtA = rng.Next(0, RESOLVER_VARIANTS);
            int rtB = rng.Next(0, RESOLVER_VARIANTS);
            int rtC = rng.Next(0, RESOLVER_VARIANTS);

            SetVaultPair(vA, a1, a2, p1, rtA);
            SetVaultPair(vB, b1, b2, p2, rtB);
            SetVaultPair(vC, c1, c2, p3, rtC);

            var insts = new List<Instruction>();
            insts.AddRange(BuildIdxPuzzle(a1));
            insts.AddRange(BuildIdxPuzzle(a2));
            insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[vA][rtA]));
            insts.AddRange(BuildIdxPuzzle(b1));
            insts.AddRange(BuildIdxPuzzle(b2));
            insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[vB][rtB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.AddRange(BuildIdxPuzzle(c1));
            insts.AddRange(BuildIdxPuzzle(c2));
            insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[vC][rtC]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildQuadVaultRetrieval(int target)
        {
            var vs = new List<int>();
            while (vs.Count < 4)
            {
                int v = rng.Next(0, VAULT_COUNT);
                if (!vs.Contains(v)) vs.Add(v);
            }
            var slots = new int[4][];
            for (int i = 0; i < 4; i++)
            {
                int s1 = AllocVaultSlot(vs[i]);
                int s2 = AllocVaultSlot(vs[i]);
                if (s1 < 0 || s2 < 0) return BuildMathRetrieval(target);
                slots[i] = new int[] { s1, s2 };
            }
            int p1 = rng.Next(int.MinValue, int.MaxValue);
            int p2 = rng.Next(int.MinValue, int.MaxValue);
            int p3 = rng.Next(int.MinValue, int.MaxValue);
            int p4 = target ^ p1 ^ p2 ^ p3;
            int[] parts = new int[] { p1, p2, p3, p4 };
            var rts = new int[4];
            for (int i = 0; i < 4; i++)
            {
                rts[i] = rng.Next(0, RESOLVER_VARIANTS);
                SetVaultPair(vs[i], slots[i][0], slots[i][1], parts[i], rts[i]);
            }
            var insts = new List<Instruction>();
            for (int i = 0; i < 4; i++)
            {
                insts.AddRange(BuildIdxPuzzle(slots[i][0]));
                insts.AddRange(BuildIdxPuzzle(slots[i][1]));
                insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[vs[i]][rts[i]]));
                if (i > 0) insts.Add(Instruction.Create(DnOpCodes.Xor));
            }
            return insts;
        }

        private List<Instruction> BuildMixedVaultRetrieval(int target)
        {
            int vA = rng.Next(0, VAULT_COUNT);
            int vB = rng.Next(0, VAULT_COUNT);
            while (vB == vA) vB = rng.Next(0, VAULT_COUNT);

            int a1 = AllocVaultSlot(vA), a2 = AllocVaultSlot(vA);
            int b1 = AllocVaultSlot(vB), b2 = AllocVaultSlot(vB);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0) return BuildMathRetrieval(target);

            int math = rng.Next(int.MinValue, int.MaxValue);
            int vaultPart = target ^ math;
            int partial = rng.Next(int.MinValue, int.MaxValue);
            int other = partial ^ vaultPart;

            int rtA = rng.Next(0, RESOLVER_VARIANTS);
            int rtB = rng.Next(0, RESOLVER_VARIANTS);
            SetVaultPair(vA, a1, a2, partial, rtA);
            SetVaultPair(vB, b1, b2, other, rtB);

            var insts = new List<Instruction>();
            insts.AddRange(BuildIdxPuzzle(a1));
            insts.AddRange(BuildIdxPuzzle(a2));
            insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[vA][rtA]));
            insts.AddRange(BuildIdxPuzzle(b1));
            insts.AddRange(BuildIdxPuzzle(b2));
            insts.Add(Instruction.Create(DnOpCodes.Call, vaultResolvers[vB][rtB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.AddRange(BuildMathRetrieval(math));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private void SetVaultPair(int vault, int s1, int s2, int target, int rt)
        {
            int v1 = vaultData[vault][s1];
            switch (rt)
            {
                case 0: vaultData[vault][s2] = v1 ^ target; break;
                case 1: vaultData[vault][s2] = unchecked(target - v1); break;
                case 2: vaultData[vault][s2] = (~v1) ^ target; break;
                case 3: vaultData[vault][s2] = unchecked(target - (~v1)); break;
                case 4: vaultData[vault][s2] = unchecked((target + v1) ^ v1); break;
                case 5: vaultData[vault][s2] = (~target) ^ v1; break;
            }
        }

        private List<Instruction> BuildMathRetrieval(int target)
        {
            var insts = new List<Instruction>();
            int p = rng.Next(0, 12);
            switch (p)
            {
                case 0:
                    int a = rng.Next(10000, 999999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a ^ target));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    int b = rng.Next(target + 10000, target + 999999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b - target));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                case 2:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~target));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    break;
                case 3:
                    int c = rng.Next(100, 99999);
                    int d = rng.Next(100, 99999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, c));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, d));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, (c + d) ^ target));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 4:
                    int sh = rng.Next(1, 5);
                    int shCheck = (target << sh);
                    if ((shCheck >> sh) == target)
                    {
                        int sv = shCheck | rng.Next(0, 1 << sh);
                        insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sv));
                        insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sh));
                        insts.Add(Instruction.Create(DnOpCodes.Shr));
                    }
                    else
                    {
                        int shf = rng.Next(int.MinValue, int.MaxValue);
                        insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, shf));
                        insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, shf ^ target));
                        insts.Add(Instruction.Create(DnOpCodes.Xor));
                    }
                    break;
                case 5:
                    int e = rng.Next(2, 99);
                    int f = rng.Next(2, 99);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, e));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, f));
                    insts.Add(Instruction.Create(DnOpCodes.Mul));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, (e * f) ^ target));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 6:
                    int g = rng.Next(100000, 9999999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, g));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - (~g)));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 7:
                    int h1 = rng.Next(int.MinValue, int.MaxValue);
                    int h2 = rng.Next(int.MinValue, int.MaxValue);
                    int h3 = target ^ h1 ^ h2;
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, h1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, h2));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, h3));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 8:
                    int mask = rng.Next(int.MinValue, int.MaxValue);
                    int p1 = target & mask;
                    int p2 = target & ~mask;
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, p1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, p2));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    break;
                case 9:
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int u3 = unchecked(target - ((u1 ^ u2) + ((u1 & u2) << 1)));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    insts.Add(Instruction.Create(DnOpCodes.Shl));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u3));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 10:
                    int n1 = rng.Next(int.MinValue, int.MaxValue);
                    int n2 = rng.Next(int.MinValue, int.MaxValue);
                    int n3 = unchecked(target ^ ((n1 & n2) ^ (~n1 & n2)));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n2));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n1));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n2));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n3));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                default:
                    int neg2 = rng.Next(int.MinValue, int.MaxValue);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target + neg2));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, neg2));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildIdxPuzzle(int target)
        {
            var insts = new List<Instruction>();
            int p = rng.Next(0, 8);
            switch (p)
            {
                case 0:
                    int k = rng.Next(10000, 999999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ target));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~target));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    break;
                case 2:
                    int a = rng.Next(target + 1000, target + 99999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a - target));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                case 3:
                    int c = rng.Next(100, 99999);
                    int d = rng.Next(100, 99999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, c));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, d));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, (c + d) ^ target));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 4:
                    int n = rng.Next(1, 5);
                    int nCheck = (target << n);
                    if ((nCheck >> n) == target)
                    {
                        int ipSv = nCheck | rng.Next(0, 1 << n);
                        insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, ipSv));
                        insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n));
                        insts.Add(Instruction.Create(DnOpCodes.Shr));
                    }
                    else
                    {
                        int ipf = rng.Next(int.MinValue, int.MaxValue);
                        insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, ipf));
                        insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, ipf ^ target));
                        insts.Add(Instruction.Create(DnOpCodes.Xor));
                    }
                    break;
                case 5:
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int u3 = unchecked(target - ((u1 ^ u2) + ((u1 & u2) << 1)));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    insts.Add(Instruction.Create(DnOpCodes.Shl));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, u3));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 6:
                    int v1 = rng.Next(int.MinValue, int.MaxValue);
                    int v2 = rng.Next(int.MinValue, int.MaxValue);
                    int v3 = unchecked(target ^ ((v1 & v2) ^ (~v1 & v2)));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, v1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, v2));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, v1));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, v2));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, v3));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                default:
                    int e = rng.Next(100000, 9999999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, e));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - (~e)));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
            }
            return insts;
        }

        private MethodDef BuildVaultResolver(ModuleDef module, FieldDef vaultField, string name, int resolveType)
        {
            var method = new MethodDefUser(name,
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultField));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultField));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            switch (resolveType)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                case 5:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    break;
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDefUser BuildDecryptor(ModuleDef module, string name, int mode)
        {
            var method = new MethodDefUser(name,
                MethodSig.CreateStatic(module.CorLibTypes.String,
                    module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.String));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Char)));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Char));

            var il = method.Body.Instructions;

            var stringConcat = module.Import(typeof(string).GetMethod("Concat", new[] { typeof(string), typeof(string) }));
            var stringGetChars = module.Import(typeof(string).GetMethod("get_Chars", new[] { typeof(int) }));
            var stringGetLength = module.Import(typeof(string).GetMethod("get_Length"));
            var stringCtorCharArr = module.Import(typeof(string).GetConstructor(new[] { typeof(char[]) }));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Call, stringConcat));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 16));
            il.Add(Instruction.Create(DnOpCodes.Shr));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 8));
            il.Add(Instruction.Create(DnOpCodes.Shr));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, stringGetLength));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Char.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[4]));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[5]));

            var loopStart = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]);
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            var loopBody = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, stringGetChars));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[6]));

            switch (mode % CIPHER_MODES)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[6]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Mul));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFFFF));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I2));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[6]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFFFF));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I2));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[6]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFFFF));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I2));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[6]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFFFF));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I2));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[6]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Mul));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFFFF));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I2));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[6]));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 8));
                    il.Add(Instruction.Create(DnOpCodes.Rem));
                    il.Add(Instruction.Create(DnOpCodes.Shl));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFFFF));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I2));
                    break;
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[5]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[5]));

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, stringGetLength));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]));
            il.Add(Instruction.Create(DnOpCodes.Newobj, stringCtorCharArr));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDefUser BuildFakeDecryptor(ModuleDef module, string name)
        {
            int sigVariant = rng.Next(0, 3);
            TypeSig[] paramTypes;
            switch (sigVariant)
            {
                case 0:
                    paramTypes = new TypeSig[] { module.CorLibTypes.String, module.CorLibTypes.Int32 };
                    break;
                case 1:
                    paramTypes = new TypeSig[] { module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.Int32, module.CorLibTypes.Int32 };
                    break;
                default:
                    paramTypes = new TypeSig[] { module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.Int32 };
                    break;
            }

            var method = new MethodDefUser(name,
                MethodSig.CreateStatic(module.CorLibTypes.String, paramTypes),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDefUser BuildVaultInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            for (int v = 0; v < VAULT_COUNT; v++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, VAULT_SIZE));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));

                for (int i = 0; i < VAULT_SIZE; i++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(engine.LoadInt(i));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, vaultData[v][i]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                }

                il.Add(Instruction.Create(DnOpCodes.Stsfld, vaults[v]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

