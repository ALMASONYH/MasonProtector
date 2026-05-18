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
    internal class NumericObfuscationProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int KEY_FIELD_COUNT = 32;
        private const int CIPHER_TABLE_SIZE = 384;
        private const int CIPHER_TABLE_COUNT = 14;
        private const int DECODER_METHOD_COUNT = 24;
        private const int FAKE_METHOD_COUNT = 24;

        private TypeDef engineType;
        private TypeDef storageType;
        private TypeDef resolverType;

        private List<FieldDef> keyFields;
        private int[] keyValues;

        private List<FieldDef> tableFields;
        private int[][] cipherTables;

        private List<MethodDef> decoderMethods;

        private int masterSeed;

        internal NumericObfuscationProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyNumericObfuscation(ModuleDef module, TypeDef modType)
        {
            keyFields = new List<FieldDef>();
            keyValues = new int[KEY_FIELD_COUNT];
            tableFields = new List<FieldDef>();
            cipherTables = new int[CIPHER_TABLE_COUNT][];
            decoderMethods = new List<MethodDef>();
            masterSeed = rng.Next(100000, int.MaxValue / 2);

            CreateEngineType(module);
            CreateStorageType(module);
            CreateResolverType(module);

            CreateKeyFields(module);
            CreateCipherTables(module);
            CreateDecoderMethods(module);
            CreateFakeMethods(module);

            EncryptIntegers(module);

            var initMethod = BuildInitializer(module);
            engineType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);
            engine.InjectCallInCctor(module, modType, initMethod);
        }

        private void CreateEngineType(ModuleDef module)
        {
            engineType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            engineType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(engineType);
            engine.injectedTypes.Add(engineType);
        }

        private void CreateStorageType(ModuleDef module)
        {
            storageType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            storageType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(storageType);
            engine.injectedTypes.Add(storageType);
        }

        private void CreateResolverType(ModuleDef module)
        {
            resolverType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            resolverType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(resolverType);
            engine.injectedTypes.Add(resolverType);
        }

        private void CreateKeyFields(ModuleDef module)
        {
            for (int i = 0; i < KEY_FIELD_COUNT; i++)
            {
                keyValues[i] = rng.Next(10000, int.MaxValue / 2);
                TypeDef host;
                int hostPick = i % 3;
                if (hostPick == 0) host = engineType;
                else if (hostPick == 1) host = storageType;
                else host = resolverType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                keyFields.Add(field);
            }

            for (int d = 0; d < rng.Next(3, 6); d++)
            {
                TypeDef host;
                int pick = rng.Next(0, 3);
                if (pick == 0) host = engineType;
                else if (pick == 1) host = storageType;
                else host = resolverType;

                host.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateCipherTables(ModuleDef module)
        {
            for (int t = 0; t < CIPHER_TABLE_COUNT; t++)
            {
                cipherTables[t] = new int[CIPHER_TABLE_SIZE];
                for (int s = 0; s < CIPHER_TABLE_SIZE; s++)
                {
                    cipherTables[t][s] = rng.Next(int.MinValue, int.MaxValue);
                }

                TypeDef host;
                int pick = t % 3;
                if (pick == 0) host = engineType;
                else if (pick == 1) host = storageType;
                else host = resolverType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                tableFields.Add(field);
            }
        }

        private void CreateDecoderMethods(ModuleDef module)
        {
            for (int d = 0; d < DECODER_METHOD_COUNT; d++)
            {
                var method = BuildDecoderMethod(module, d);
                TypeDef host;
                int pick = d % 3;
                if (pick == 0) host = engineType;
                else if (pick == 1) host = storageType;
                else host = resolverType;

                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                decoderMethods.Add(method);
            }
        }

        private void CreateFakeMethods(ModuleDef module)
        {
            for (int f = 0; f < FAKE_METHOD_COUNT; f++)
            {
                var method = BuildFakeMethod(module, f);
                TypeDef host;
                int pick = rng.Next(0, 3);
                if (pick == 0) host = engineType;
                else if (pick == 1) host = storageType;
                else host = resolverType;

                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
            }
        }

        private MethodDef BuildDecoderMethod(ModuleDef module, int variant)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            switch (variant % DECODER_METHOD_COUNT)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 5:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 6:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Neg));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterSeed));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterSeed));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
            }

            return method;
        }

        private MethodDef BuildFakeMethod(ModuleDef module, int variant)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            switch (variant % FAKE_METHOD_COUNT)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Mul));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                    il.Add(Instruction.Create(DnOpCodes.Shl));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Neg));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Or));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
            }

            return method;
        }

        private void EncryptIntegers(ModuleDef module)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    try
                    {
                        EncryptMethodIntegers(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }
        }

        private void EncryptMethodIntegers(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            for (int i = il.Count - 1; i >= 0; i--)
            {
                if (!engine.IsIntLoad(il[i])) continue;
                int val = engine.ExtractInt(il[i]);
                if (val == int.MinValue) continue;
                if (val >= -1 && val <= 8) continue;
                if (rng.Next(0, 4) != 0) continue;

                int pattern = rng.Next(0, 8);
                var replacement = new List<Instruction>();

                switch (pattern)
                {
                    case 0:
                        replacement = EmitKeyXor(module, val);
                        break;
                    case 1:
                        replacement = EmitKeyAdd(module, val);
                        break;
                    case 2:
                        replacement = EmitMasterSeedXor(module, val);
                        break;
                    case 3:
                        replacement = EmitTableLookup(module, val);
                        break;
                    case 4:
                        replacement = EmitDoubleTableXor(module, val);
                        break;
                    case 5:
                        replacement = EmitNotXor(module, val);
                        break;
                    case 6:
                        replacement = EmitChainField(module, val);
                        break;
                    default:
                        replacement = EmitRotorCompute(module, val);
                        break;
                }

                if (replacement.Count == 0) continue;

                il[i].OpCode = replacement[0].OpCode;
                il[i].Operand = replacement[0].Operand;
                for (int r = 1; r < replacement.Count; r++)
                    il.Insert(i + r, replacement[r]);
            }
        }

        private List<Instruction> EmitKeyXor(ModuleDef module, int target)
        {
            var insts = new List<Instruction>();
            int keyIdx = rng.Next(0, KEY_FIELD_COUNT);
            int keyVal = keyValues[keyIdx];
            int encoded = target ^ keyVal;

            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyIdx]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> EmitKeyAdd(ModuleDef module, int target)
        {
            var insts = new List<Instruction>();
            int keyIdx = rng.Next(0, KEY_FIELD_COUNT);
            int keyVal = keyValues[keyIdx];
            int encoded = target - keyVal;

            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyIdx]));
            insts.Add(Instruction.Create(DnOpCodes.Add));
            return insts;
        }

        private List<Instruction> EmitMasterSeedXor(ModuleDef module, int target)
        {
            var insts = new List<Instruction>();
            int keyIdx = rng.Next(0, KEY_FIELD_COUNT);
            int keyVal = keyValues[keyIdx];
            int intermediate = target ^ masterSeed;
            int encoded = intermediate ^ keyVal;

            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyIdx]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterSeed));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> EmitTableLookup(ModuleDef module, int target)
        {
            var insts = new List<Instruction>();
            int tableIdx = rng.Next(0, CIPHER_TABLE_COUNT);
            int slot = rng.Next(0, CIPHER_TABLE_SIZE);
            int tableVal = cipherTables[tableIdx][slot];
            int encoded = target ^ tableVal;

            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, tableFields[tableIdx]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, slot));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> EmitDoubleTableXor(ModuleDef module, int target)
        {
            var insts = new List<Instruction>();
            int tblA = rng.Next(0, CIPHER_TABLE_COUNT);
            int tblB = rng.Next(0, CIPHER_TABLE_COUNT);
            while (tblB == tblA && CIPHER_TABLE_COUNT > 1) tblB = rng.Next(0, CIPHER_TABLE_COUNT);
            int slotA = rng.Next(0, CIPHER_TABLE_SIZE);
            int slotB = rng.Next(0, CIPHER_TABLE_SIZE);
            int valA = cipherTables[tblA][slotA];
            int valB = cipherTables[tblB][slotB];
            int encoded = target ^ valA ^ valB;

            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, tableFields[tblA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, slotA));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, tableFields[tblB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, slotB));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> EmitNotXor(ModuleDef module, int target)
        {
            var insts = new List<Instruction>();
            int keyIdx = rng.Next(0, KEY_FIELD_COUNT);
            int keyVal = keyValues[keyIdx];
            int notKey = ~keyVal;
            int encoded = target ^ notKey;

            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyIdx]));
            insts.Add(Instruction.Create(DnOpCodes.Not));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> EmitChainField(ModuleDef module, int target)
        {
            var insts = new List<Instruction>();
            int keyA = rng.Next(0, KEY_FIELD_COUNT);
            int keyB = rng.Next(0, KEY_FIELD_COUNT);
            while (keyB == keyA && KEY_FIELD_COUNT > 1) keyB = rng.Next(0, KEY_FIELD_COUNT);
            int valA = keyValues[keyA];
            int valB = keyValues[keyB];
            int combined = valA ^ valB;
            int encoded = target ^ combined;

            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyA]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> EmitRotorCompute(ModuleDef module, int target)
        {
            var insts = new List<Instruction>();
            int keyIdx = rng.Next(0, KEY_FIELD_COUNT);
            int keyVal = keyValues[keyIdx];
            int tableIdx = rng.Next(0, CIPHER_TABLE_COUNT);
            int slot = rng.Next(0, CIPHER_TABLE_SIZE);
            int tableVal = cipherTables[tableIdx][slot];
            int rotor = keyVal ^ tableVal;
            int encoded = target - rotor;

            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyIdx]));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, tableFields[tableIdx]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, slot));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Add));
            return insts;
        }

        private MethodDefUser BuildInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            for (int i = 0; i < KEY_FIELD_COUNT; i++)
            {
                int pattern = rng.Next(0, 5);
                switch (pattern)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, keyValues[i]));
                        break;
                    case 1:
                    {
                        int k = rng.Next(int.MinValue, int.MaxValue);
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ keyValues[i]));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        break;
                    }
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~keyValues[i]));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        break;
                    case 3:
                    {
                        int a = rng.Next(1000, 999999);
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a - keyValues[i]));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        break;
                    }
                    default:
                    {
                        int p = rng.Next(int.MinValue, int.MaxValue);
                        int q = rng.Next(int.MinValue, int.MaxValue);
                        int r = keyValues[i] ^ p ^ q;
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, p));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, q));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        break;
                    }
                }
                il.Add(Instruction.Create(DnOpCodes.Stsfld, keyFields[i]));
            }

            for (int t = 0; t < CIPHER_TABLE_COUNT; t++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, CIPHER_TABLE_SIZE));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, tableFields[t]));

                int runStart = 0;
                while (runStart < CIPHER_TABLE_SIZE)
                {
                    int runLen = Math.Min(rng.Next(4, 20), CIPHER_TABLE_SIZE - runStart);
                    int initPattern = rng.Next(0, 3);

                    for (int s = runStart; s < runStart + runLen; s++)
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldsfld, tableFields[t]));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, s));

                        switch (initPattern)
                        {
                            case 0:
                                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, cipherTables[t][s]));
                                break;
                            case 1:
                            {
                                int xk = rng.Next(int.MinValue, int.MaxValue);
                                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, xk));
                                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, xk ^ cipherTables[t][s]));
                                il.Add(Instruction.Create(DnOpCodes.Xor));
                                break;
                            }
                            default:
                                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~cipherTables[t][s]));
                                il.Add(Instruction.Create(DnOpCodes.Not));
                                break;
                        }

                        il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                    }

                    runStart += runLen;
                }
            }

            EmitInitializerJunk(il, module);

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private void EmitInitializerJunk(IList<Instruction> il, ModuleDef module)
        {
            int junkCount = rng.Next(5, 12);
            for (int j = 0; j < junkCount; j++)
            {
                int kind = rng.Next(0, 4);
                switch (kind)
                {
                    case 0:
                    {
                        int fIdx = rng.Next(0, KEY_FIELD_COUNT);
                        il.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[fIdx]));
                        il.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[fIdx]));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                    case 1:
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                    case 2:
                    {
                        int tIdx = rng.Next(0, CIPHER_TABLE_COUNT);
                        int sIdx = rng.Next(0, CIPHER_TABLE_SIZE);
                        il.Add(Instruction.Create(DnOpCodes.Ldsfld, tableFields[tIdx]));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, sIdx));
                        il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
                        il.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                    default:
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterSeed));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                }
            }
        }
    }
}

