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
    internal class ArrayEncryptionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int CIPHER_KEY_COUNT = 32;
        private const int CIPHER_TABLE_COUNT = 16;
        private const int CIPHER_TABLE_SIZE = 384;
        private const int CIPHER_DECODER_COUNT = 28;
        private const int CIPHER_FAKE_COUNT = 32;
        private const int CIPHER_SCRAMBLER_COUNT = 18;
        private const int CIPHER_MIXER_COUNT = 12;

        private TypeDef cipherType;
        private TypeDef vaultType;
        private TypeDef decoderType;
        private List<FieldDef> cipherKeys;
        private int[] cipherKeyValues;
        private List<FieldDef> cipherTables;
        private List<int[]> cipherTableData;
        private List<int[]> cipherPermutations;
        private int[] cipherAllocPtrs;
        private List<MethodDef> decoderMethods;
        private List<MethodDef> scramblerMethods;
        private FieldDef masterField;
        private int masterValue;
        private FieldDef seedField;
        private int seedValue;
        private FieldDef rotorField;
        private int rotorValue;
        private FieldDef counterField;
        private int counterValue;
        private FieldDef deltaField;
        private int deltaValue;

        internal ArrayEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyArrayEncryption(ModuleDef module, TypeDef modType)
        {
            cipherKeys = new List<FieldDef>();
            cipherKeyValues = new int[CIPHER_KEY_COUNT];
            cipherTables = new List<FieldDef>();
            cipherTableData = new List<int[]>();
            cipherPermutations = new List<int[]>();
            cipherAllocPtrs = new int[CIPHER_TABLE_COUNT];
            decoderMethods = new List<MethodDef>();
            scramblerMethods = new List<MethodDef>();

            CreateCipherType(module);
            CreateVaultType(module);
            CreateDecoderType(module);
            CreateCipherKeys(module);
            CreateCipherTables(module);
            CreateDecoderMethods(module);
            CreateScramblerMethods(module);
            CreateFakeMethods(module);
            CreateFakeFields(module);

            int counter = 0;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    try
                    {
                        counter += EncryptIntegers(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            if (counter > 0)
            {
                var init = BuildInitializer(module);
                cipherType.Methods.Add(init);
                engine.injectedMethods.Add(init);
                engine.InjectCallInCctor(module, modType, init);
            }
        }

        private void CreateCipherType(ModuleDef module)
        {
            cipherType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            cipherType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(cipherType);
            engine.injectedTypes.Add(cipherType);

            masterValue = rng.Next(100000, int.MaxValue / 2);
            masterField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            cipherType.Fields.Add(masterField);

            seedValue = rng.Next(100000, int.MaxValue / 2);
            seedField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            cipherType.Fields.Add(seedField);

            rotorValue = rng.Next(1, int.MaxValue / 4);
            rotorField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            cipherType.Fields.Add(rotorField);

            counterValue = rng.Next(1, 65536);
            counterField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            cipherType.Fields.Add(counterField);

            deltaValue = rng.Next(1, int.MaxValue / 8);
            deltaField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            cipherType.Fields.Add(deltaField);

            for (int i = 0; i < rng.Next(5, 10); i++)
            {
                cipherType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateVaultType(ModuleDef module)
        {
            vaultType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vaultType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(vaultType);
            engine.injectedTypes.Add(vaultType);

            for (int i = 0; i < rng.Next(8, 14); i++)
            {
                TypeSig ft;
                int t = rng.Next(0, 5);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = module.CorLibTypes.Boolean;
                else if (t == 3) ft = new SZArraySig(module.CorLibTypes.Int32);
                else ft = module.CorLibTypes.Byte;

                vaultType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateDecoderType(ModuleDef module)
        {
            decoderType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            decoderType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(decoderType);
            engine.injectedTypes.Add(decoderType);

            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                decoderType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateCipherKeys(ModuleDef module)
        {
            for (int k = 0; k < CIPHER_KEY_COUNT; k++)
            {
                cipherKeyValues[k] = rng.Next(int.MinValue, int.MaxValue);
                TypeDef host;
                if (k % 3 == 0) host = cipherType;
                else if (k % 3 == 1) host = vaultType;
                else host = decoderType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                cipherKeys.Add(field);
            }
        }

        private void CreateCipherTables(ModuleDef module)
        {
            for (int t = 0; t < CIPHER_TABLE_COUNT; t++)
            {
                TypeDef host;
                if (t % 3 == 0) host = cipherType;
                else if (t % 3 == 1) host = vaultType;
                else host = decoderType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                cipherTables.Add(field);

                var data = new int[CIPHER_TABLE_SIZE];
                for (int i = 0; i < CIPHER_TABLE_SIZE; i++)
                    data[i] = rng.Next(int.MinValue, int.MaxValue);
                cipherTableData.Add(data);

                var perm = new int[CIPHER_TABLE_SIZE];
                for (int i = 0; i < CIPHER_TABLE_SIZE; i++) perm[i] = i;
                for (int i = CIPHER_TABLE_SIZE - 1; i > 0; i--)
                {
                    int j = rng.Next(0, i + 1);
                    int tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
                }
                cipherPermutations.Add(perm);
                cipherAllocPtrs[t] = 0;
            }
        }

        private void CreateDecoderMethods(ModuleDef module)
        {
            for (int d = 0; d < CIPHER_DECODER_COUNT; d++)
            {
                var method = BuildDecoderMethod(module, d);
                TypeDef host;
                if (d % 3 == 0) host = cipherType;
                else if (d % 3 == 1) host = vaultType;
                else host = decoderType;
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                decoderMethods.Add(method);
            }
        }

        private void CreateScramblerMethods(ModuleDef module)
        {
            for (int s = 0; s < CIPHER_SCRAMBLER_COUNT; s++)
            {
                var method = BuildScramblerMethod(module, s);
                TypeDef host;
                if (s % 2 == 0) host = cipherType;
                else host = decoderType;
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                scramblerMethods.Add(method);
            }
        }

        private void CreateFakeMethods(ModuleDef module)
        {
            TypeDef[] hosts = new TypeDef[] { cipherType, vaultType, decoderType };
            for (int f = 0; f < CIPHER_FAKE_COUNT; f++)
            {
                var fake = BuildFakeDecoder(module);
                hosts[f % hosts.Length].Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }
        }

        private void CreateFakeFields(ModuleDef module)
        {
            TypeDef[] hosts = new TypeDef[] { cipherType, vaultType, decoderType };
            for (int i = 0; i < rng.Next(10, 18); i++)
            {
                var host = hosts[rng.Next(hosts.Length)];
                TypeSig ft;
                int t = rng.Next(0, 6);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = module.CorLibTypes.Boolean;
                else if (t == 3) ft = module.CorLibTypes.Byte;
                else if (t == 4) ft = module.CorLibTypes.Double;
                else ft = new SZArraySig(module.CorLibTypes.Int32);

                host.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private int AllocSlot(int tableIdx)
        {
            if (cipherAllocPtrs[tableIdx] >= CIPHER_TABLE_SIZE) return -1;
            return cipherPermutations[tableIdx][cipherAllocPtrs[tableIdx]++];
        }

        private int EncryptIntegers(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            int encrypted = 0;

            for (int i = 0; i < il.Count; i++)
            {
                if (!engine.IsIntLoad(il[i])) continue;
                int val = engine.ExtractInt(il[i]);
                if (val == int.MinValue) continue;
                if (val >= -1 && val <= 8) continue;
                if (rng.Next(0, 5) != 0) continue;

                int pattern = rng.Next(0, 8);
                List<Instruction> replacement = null;

                switch (pattern)
                {
                    case 0: replacement = BuildKeyXor(val); break;
                    case 1: replacement = BuildKeyAdd(val); break;
                    case 2: replacement = BuildMasterXor(val); break;
                    case 3: replacement = BuildSeedCompute(val); break;
                    case 4: replacement = BuildRotorCompute(val); break;
                    case 5: replacement = BuildDeltaCompute(val); break;
                    case 6: replacement = BuildTableLookup(val); break;
                    default: replacement = BuildDoubleTableLookup(val); break;
                }

                if (replacement == null || replacement.Count == 0) continue;

                il[i].OpCode = replacement[0].OpCode;
                il[i].Operand = replacement[0].Operand;
                for (int j = 1; j < replacement.Count; j++)
                    il.Insert(i + j, replacement[j]);
                i += replacement.Count - 1;
                encrypted++;
            }

            return encrypted;
        }

        private List<Instruction> BuildKeyXor(int target)
        {
            int k = rng.Next(0, CIPHER_KEY_COUNT);
            int diff = target ^ cipherKeyValues[k];
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, cipherKeys[k]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildKeyAdd(int target)
        {
            int k = rng.Next(0, CIPHER_KEY_COUNT);
            int diff = target - cipherKeyValues[k];
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, cipherKeys[k]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Add));
            return insts;
        }

        private List<Instruction> BuildMasterXor(int target)
        {
            int diff = target ^ masterValue;
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, masterField));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildSeedCompute(int target)
        {
            int pattern = rng.Next(0, 3);
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, seedField));
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target ^ seedValue));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - seedValue));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - (~seedValue)));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildRotorCompute(int target)
        {
            int diff = target ^ rotorValue;
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, rotorField));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildDeltaCompute(int target)
        {
            int diff = target - deltaValue;
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, deltaField));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Add));
            return insts;
        }

        private List<Instruction> BuildTableLookup(int target)
        {
            int t = rng.Next(0, CIPHER_TABLE_COUNT);
            int s1 = AllocSlot(t);
            int s2 = AllocSlot(t);
            if (s1 < 0 || s2 < 0) return BuildFallback(target);

            cipherTableData[t][s2] = cipherTableData[t][s1] ^ target;

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, cipherTables[t]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, cipherTables[t]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildDoubleTableLookup(int target)
        {
            int tA = rng.Next(0, CIPHER_TABLE_COUNT);
            int tB = rng.Next(0, CIPHER_TABLE_COUNT);
            while (tB == tA && CIPHER_TABLE_COUNT > 1) tB = rng.Next(0, CIPHER_TABLE_COUNT);

            int a1 = AllocSlot(tA); int a2 = AllocSlot(tA);
            int b1 = AllocSlot(tB); int b2 = AllocSlot(tB);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0) return BuildFallback(target);

            int partial = rng.Next(int.MinValue, int.MaxValue);
            int other = partial ^ target;
            cipherTableData[tA][a2] = cipherTableData[tA][a1] ^ partial;
            cipherTableData[tB][b2] = cipherTableData[tB][b1] ^ other;

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, cipherTables[tA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, cipherTables[tA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, cipherTables[tB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, cipherTables[tB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildFallback(int target)
        {
            int k = rng.Next(int.MinValue, int.MaxValue);
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ target));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private MethodDef BuildDecoderMethod(ModuleDef module, int variant)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            switch (variant % 5)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, masterField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, seedField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    break;
            }

            for (int n = 0; n < rng.Next(2, 5); n++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                il.Add(Instruction.Create(DnOpCodes.Pop));
                il.Add(Instruction.Create(DnOpCodes.Pop));
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildScramblerMethod(ModuleDef module, int variant)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            switch (variant % 3)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                    break;
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildFakeDecoder(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int n = 0; n < rng.Next(3, 8); n++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                int op = rng.Next(0, 3);
                if (op == 0) il.Add(Instruction.Create(DnOpCodes.Xor));
                else if (op == 1) il.Add(Instruction.Create(DnOpCodes.Add));
                else il.Add(Instruction.Create(DnOpCodes.Sub));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDefUser BuildInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, masterField));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, seedValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, seedField));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rotorValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, rotorField));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, counterValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, counterField));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, deltaValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, deltaField));

            for (int k = 0; k < CIPHER_KEY_COUNT; k++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, cipherKeyValues[k]));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, cipherKeys[k]));
            }

            for (int t = 0; t < CIPHER_TABLE_COUNT; t++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, CIPHER_TABLE_SIZE));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));

                for (int i = 0; i < CIPHER_TABLE_SIZE; i++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(engine.LoadInt(i));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, cipherTableData[t][i]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                }

                il.Add(Instruction.Create(DnOpCodes.Stsfld, cipherTables[t]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

