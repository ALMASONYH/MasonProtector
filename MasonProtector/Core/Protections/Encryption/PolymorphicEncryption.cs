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
    internal class PolymorphicEncryptionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int POLY_VAULT_COUNT = 24;
        private const int POLY_VAULT_SIZE = 576;
        private const int POLY_KEY_COUNT = 48;
        private const int POLY_DECODER_COUNT = 32;
        private const int POLY_FAKE_COUNT = 32;
        private const int POLY_SCRAMBLER_COUNT = 18;
        private const int POLY_MIXER_COUNT = 12;
        private const int POLY_CHAIN_LENGTH = 9;

        private List<TypeDef> vaultTypes;
        private List<FieldDef> vaultArrays;
        private List<int[]> vaultData;
        private List<int[]> vaultPermutations;
        private int[] vaultAllocPtrs;
        private List<FieldDef> keyFields;
        private int[] keyValues;
        private List<MethodDef> decoderMethods;
        private List<MethodDef> scramblerMethods;
        private List<MethodDef> mixerMethods;
        private FieldDef masterSeedField;
        private int masterSeedValue;
        private FieldDef auxSeedField;
        private int auxSeedValue;
        private FieldDef rotorField;
        private int rotorValue;
        private FieldDef counterField;
        private int counterValue;
        private List<FieldDef> chainFields;
        private int[] chainValues;
        private TypeDef engineType;
        private TypeDef storageType;
        private TypeDef mixerType;

        internal PolymorphicEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyPolymorphicEncryption(ModuleDef module, TypeDef modType)
        {
            vaultTypes = new List<TypeDef>();
            vaultArrays = new List<FieldDef>();
            vaultData = new List<int[]>();
            vaultPermutations = new List<int[]>();
            vaultAllocPtrs = new int[POLY_VAULT_COUNT];
            keyFields = new List<FieldDef>();
            keyValues = new int[POLY_KEY_COUNT];
            decoderMethods = new List<MethodDef>();
            scramblerMethods = new List<MethodDef>();
            mixerMethods = new List<MethodDef>();
            chainFields = new List<FieldDef>();
            chainValues = new int[POLY_CHAIN_LENGTH];

            CreateEngineType(module);
            CreateStorageType(module);
            CreateMixerType(module);
            CreateVaults(module);
            CreateKeyFields(module);
            CreateChainFields(module);
            CreateDecoderMethods(module);
            CreateScramblerMethods(module);
            CreateMixerMethods(module);
            CreateFakeMethods(module);
            CreateFakeFieldNoise(module);

            int counter = 0;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    try
                    {
                        counter += EncryptConstants(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            if (counter > 0)
            {
                var init = BuildInitializer(module);
                engineType.Methods.Add(init);
                engine.injectedMethods.Add(init);
                engine.InjectCallInCctor(module, modType, init);
            }
        }

        private void CreateEngineType(ModuleDef module)
        {
            engineType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            engineType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(engineType);
            engine.injectedTypes.Add(engineType);

            masterSeedValue = rng.Next(100000, int.MaxValue / 2);
            masterSeedField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            engineType.Fields.Add(masterSeedField);

            auxSeedValue = rng.Next(100000, int.MaxValue / 2);
            auxSeedField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            engineType.Fields.Add(auxSeedField);

            rotorValue = rng.Next(1, int.MaxValue / 4);
            rotorField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            engineType.Fields.Add(rotorField);

            counterValue = rng.Next(1, 65536);
            counterField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            engineType.Fields.Add(counterField);

            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                engineType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateStorageType(ModuleDef module)
        {
            storageType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            storageType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(storageType);
            engine.injectedTypes.Add(storageType);

            for (int i = 0; i < rng.Next(6, 12); i++)
            {
                storageType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateMixerType(ModuleDef module)
        {
            mixerType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            mixerType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(mixerType);
            engine.injectedTypes.Add(mixerType);

            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                mixerType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int64),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateVaults(ModuleDef module)
        {
            for (int v = 0; v < POLY_VAULT_COUNT; v++)
            {
                TypeDef host;
                int hostChoice = v % 3;
                if (hostChoice == 0) host = engineType;
                else if (hostChoice == 1) host = storageType;
                else host = mixerType;

                var arrField = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(arrField);
                vaultArrays.Add(arrField);
                vaultTypes.Add(host);

                var data = new int[POLY_VAULT_SIZE];
                for (int i = 0; i < POLY_VAULT_SIZE; i++)
                    data[i] = rng.Next(int.MinValue, int.MaxValue);
                vaultData.Add(data);

                var perm = new int[POLY_VAULT_SIZE];
                for (int i = 0; i < POLY_VAULT_SIZE; i++) perm[i] = i;
                for (int i = POLY_VAULT_SIZE - 1; i > 0; i--)
                {
                    int j = rng.Next(0, i + 1);
                    int tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
                }
                vaultPermutations.Add(perm);
                vaultAllocPtrs[v] = 0;
            }
        }

        private void CreateKeyFields(ModuleDef module)
        {
            for (int k = 0; k < POLY_KEY_COUNT; k++)
            {
                keyValues[k] = rng.Next(int.MinValue, int.MaxValue);
                TypeDef host;
                int hostChoice = k % 3;
                if (hostChoice == 0) host = engineType;
                else if (hostChoice == 1) host = storageType;
                else host = mixerType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                keyFields.Add(field);
            }
        }

        private void CreateChainFields(ModuleDef module)
        {
            for (int c = 0; c < POLY_CHAIN_LENGTH; c++)
            {
                chainValues[c] = rng.Next(100000, int.MaxValue / 2);
                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                engineType.Fields.Add(field);
                chainFields.Add(field);
            }
        }

        private void CreateDecoderMethods(ModuleDef module)
        {
            for (int d = 0; d < POLY_DECODER_COUNT; d++)
            {
                var method = BuildDecoderMethod(module, d);
                TypeDef host;
                int hostChoice = d % 3;
                if (hostChoice == 0) host = engineType;
                else if (hostChoice == 1) host = storageType;
                else host = mixerType;
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                decoderMethods.Add(method);
            }
        }

        private void CreateScramblerMethods(ModuleDef module)
        {
            for (int s = 0; s < POLY_SCRAMBLER_COUNT; s++)
            {
                var method = BuildScramblerMethod(module, s);
                TypeDef host;
                if (s % 2 == 0) host = engineType;
                else host = mixerType;
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                scramblerMethods.Add(method);
            }
        }

        private void CreateMixerMethods(ModuleDef module)
        {
            for (int m = 0; m < POLY_MIXER_COUNT; m++)
            {
                var method = BuildMixerMethod(module, m);
                mixerType.Methods.Add(method);
                engine.injectedMethods.Add(method);
                mixerMethods.Add(method);
            }
        }

        private void CreateFakeMethods(ModuleDef module)
        {
            for (int f = 0; f < POLY_FAKE_COUNT; f++)
            {
                var fake = BuildFakeDecoder(module);
                TypeDef host;
                int hostChoice = f % 3;
                if (hostChoice == 0) host = engineType;
                else if (hostChoice == 1) host = storageType;
                else host = mixerType;
                host.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }
        }

        private void CreateFakeFieldNoise(ModuleDef module)
        {
            TypeDef[] hosts = new TypeDef[] { engineType, storageType, mixerType };
            for (int i = 0; i < rng.Next(8, 16); i++)
            {
                var host = hosts[rng.Next(hosts.Length)];
                TypeSig fieldType;
                int t = rng.Next(0, 5);
                if (t == 0) fieldType = module.CorLibTypes.Int32;
                else if (t == 1) fieldType = module.CorLibTypes.Int64;
                else if (t == 2) fieldType = module.CorLibTypes.Boolean;
                else if (t == 3) fieldType = module.CorLibTypes.Byte;
                else fieldType = module.CorLibTypes.Double;

                host.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(fieldType),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private int AllocSlot(int vaultIdx)
        {
            if (vaultAllocPtrs[vaultIdx] >= POLY_VAULT_SIZE) return -1;
            return vaultPermutations[vaultIdx][vaultAllocPtrs[vaultIdx]++];
        }

        private int EncryptConstants(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            int encrypted = 0;

            for (int i = 0; i < il.Count; i++)
            {
                if (!engine.IsIntLoad(il[i])) continue;
                int val = engine.ExtractInt(il[i]);
                if (val == int.MinValue) continue;
                if (val >= -1 && val <= 8) continue;
                if (rng.Next(0, 4) != 0) continue;

                int pattern = rng.Next(0, 10);
                List<Instruction> replacement = null;

                switch (pattern)
                {
                    case 0: replacement = BuildVaultXorLookup(val); break;
                    case 1: replacement = BuildVaultAddLookup(val); break;
                    case 2: replacement = BuildDoubleVaultXor(val); break;
                    case 3: replacement = BuildKeyFieldXor(val); break;
                    case 4: replacement = BuildKeyFieldAdd(val); break;
                    case 5: replacement = BuildMasterSeedXor(val); break;
                    case 6: replacement = BuildAuxSeedCompute(val); break;
                    case 7: replacement = BuildChainCompute(val); break;
                    case 8: replacement = BuildRotorCompute(val); break;
                    default: replacement = BuildTripleVaultXor(val); break;
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

        private List<Instruction> BuildVaultXorLookup(int target)
        {
            int v = rng.Next(0, POLY_VAULT_COUNT);
            int s1 = AllocSlot(v);
            int s2 = AllocSlot(v);
            if (s1 < 0 || s2 < 0) return BuildFallback(target);

            vaultData[v][s2] = vaultData[v][s1] ^ target;

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[v]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[v]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildVaultAddLookup(int target)
        {
            int v = rng.Next(0, POLY_VAULT_COUNT);
            int s1 = AllocSlot(v);
            int s2 = AllocSlot(v);
            if (s1 < 0 || s2 < 0) return BuildFallback(target);

            vaultData[v][s2] = target - vaultData[v][s1];

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[v]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[v]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Add));
            return insts;
        }

        private List<Instruction> BuildDoubleVaultXor(int target)
        {
            int vA = rng.Next(0, POLY_VAULT_COUNT);
            int vB = rng.Next(0, POLY_VAULT_COUNT);
            while (vB == vA && POLY_VAULT_COUNT > 1) vB = rng.Next(0, POLY_VAULT_COUNT);

            int a1 = AllocSlot(vA); int a2 = AllocSlot(vA);
            int b1 = AllocSlot(vB); int b2 = AllocSlot(vB);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0) return BuildFallback(target);

            int partial = rng.Next(int.MinValue, int.MaxValue);
            int other = partial ^ target;
            vaultData[vA][a2] = vaultData[vA][a1] ^ partial;
            vaultData[vB][b2] = vaultData[vB][b1] ^ other;

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildTripleVaultXor(int target)
        {
            int vA = rng.Next(0, POLY_VAULT_COUNT);
            int vB = rng.Next(0, POLY_VAULT_COUNT);
            while (vB == vA && POLY_VAULT_COUNT > 1) vB = rng.Next(0, POLY_VAULT_COUNT);
            int vC = rng.Next(0, POLY_VAULT_COUNT);
            while ((vC == vA || vC == vB) && POLY_VAULT_COUNT > 2) vC = rng.Next(0, POLY_VAULT_COUNT);

            int a1 = AllocSlot(vA); int a2 = AllocSlot(vA);
            int b1 = AllocSlot(vB); int b2 = AllocSlot(vB);
            int c1 = AllocSlot(vC); int c2 = AllocSlot(vC);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0 || c1 < 0 || c2 < 0)
                return BuildFallback(target);

            int p1 = rng.Next(int.MinValue, int.MaxValue);
            int p2 = rng.Next(int.MinValue, int.MaxValue);
            int p3 = target ^ p1 ^ p2;
            vaultData[vA][a2] = vaultData[vA][a1] ^ p1;
            vaultData[vB][b2] = vaultData[vB][b1] ^ p2;
            vaultData[vC][c2] = vaultData[vC][c1] ^ p3;

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vC]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, c1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, vaultArrays[vC]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, c2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildKeyFieldXor(int target)
        {
            int k = rng.Next(0, POLY_KEY_COUNT);
            int diff = target ^ keyValues[k];
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[k]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildKeyFieldAdd(int target)
        {
            int k = rng.Next(0, POLY_KEY_COUNT);
            int diff = target - keyValues[k];
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[k]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Add));
            return insts;
        }

        private List<Instruction> BuildMasterSeedXor(int target)
        {
            int diff = target ^ masterSeedValue;
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, masterSeedField));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildAuxSeedCompute(int target)
        {
            int pattern = rng.Next(0, 3);
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, auxSeedField));
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target ^ auxSeedValue));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - auxSeedValue));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - (~auxSeedValue)));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildChainCompute(int target)
        {
            int idx = rng.Next(0, POLY_CHAIN_LENGTH);
            int diff = target ^ chainValues[idx];
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, chainFields[idx]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildRotorCompute(int target)
        {
            int pattern = rng.Next(0, 3);
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, rotorField));
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target ^ rotorValue));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, rotorValue - target));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - rotorValue));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
            }
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

            int ops = variant % 6;
            switch (ops)
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
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, masterSeedField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, auxSeedField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, rotorField));
                    il.Add(Instruction.Create(DnOpCodes.Add));
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
            var il = method.Body.Instructions;

            switch (variant % 3)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    break;
            }

            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildMixerMethod(ModuleDef module, int variant)
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
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            for (int r = 0; r < rng.Next(3, 6); r++)
            {
                int op = rng.Next(0, 4);
                switch (op)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 1:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
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

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterSeedValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, masterSeedField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, auxSeedValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, auxSeedField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rotorValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, rotorField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, counterValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, counterField));

            for (int k = 0; k < POLY_KEY_COUNT; k++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, keyValues[k]));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, keyFields[k]));
            }

            for (int c = 0; c < POLY_CHAIN_LENGTH; c++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, chainValues[c]));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, chainFields[c]));
            }

            for (int v = 0; v < POLY_VAULT_COUNT; v++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, POLY_VAULT_SIZE));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));

                for (int i = 0; i < POLY_VAULT_SIZE; i++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(engine.LoadInt(i));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, vaultData[v][i]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                }

                il.Add(Instruction.Create(DnOpCodes.Stsfld, vaultArrays[v]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

