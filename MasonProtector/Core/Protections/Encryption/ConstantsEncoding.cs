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
    internal class ConstantsEncodingProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int TABLE_COUNT = 16;
        private const int TABLE_SIZE = 512;
        private List<FieldDef> constTables;
        private List<int[]> tableData;
        private List<int[]> tablePermutation;
        private int[] tableAllocIdx;
        private List<MethodDef> decoderMethods;
        private TypeDef containerType;
        private FieldDef masterSeed;
        private int masterSeedValue;

        internal ConstantsEncodingProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyConstantsEncoding(ModuleDef module, TypeDef modType)
        {
            constTables = new List<FieldDef>();
            tableData = new List<int[]>();
            tablePermutation = new List<int[]>();
            tableAllocIdx = new int[TABLE_COUNT];
            decoderMethods = new List<MethodDef>();

            containerType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            containerType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(containerType);
            engine.injectedTypes.Add(containerType);

            masterSeedValue = rng.Next(100000, int.MaxValue / 2);
            masterSeed = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            containerType.Fields.Add(masterSeed);

            for (int d = 0; d < rng.Next(3, 7); d++)
            {
                containerType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }

            for (int t = 0; t < TABLE_COUNT; t++)
            {
                var tableField = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                containerType.Fields.Add(tableField);
                constTables.Add(tableField);

                var data = new int[TABLE_SIZE];
                for (int i = 0; i < TABLE_SIZE; i++)
                    data[i] = rng.Next(int.MinValue, int.MaxValue);
                tableData.Add(data);

                var perm = new int[TABLE_SIZE];
                for (int i = 0; i < TABLE_SIZE; i++) perm[i] = i;
                for (int i = TABLE_SIZE - 1; i > 0; i--)
                {
                    int j = rng.Next(0, i + 1);
                    int tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
                }
                tablePermutation.Add(perm);
                tableAllocIdx[t] = 0;
            }

            for (int m = 0; m < 8; m++)
            {
                var decoder = BuildDecoderMethod(module, m);
                containerType.Methods.Add(decoder);
                engine.injectedMethods.Add(decoder);
                decoderMethods.Add(decoder);
            }

            for (int f = 0; f < 4; f++)
            {
                var fake = BuildFakeDecoder(module);
                containerType.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }

            int counter = 0;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    try
                    {
                        counter += EncodeConstants(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsCompilerGenerated(type)) continue;
                if (!engine.IsWinFormsType(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (method.HasGenericParameters) continue;
                    if (engine.IsMethodUserExcluded(method)) continue;

                    bool isDesignerScope = method.Name == "InitializeComponent"
                        || engine.designerSplitSubMethods.Contains(method);
                    if (!isDesignerScope) continue;
                    try
                    {
                        counter += EncodeConstants(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            if (counter > 0)
            {
                var initMethod = BuildTableInitializer(module);
                containerType.Methods.Add(initMethod);
                engine.injectedMethods.Add(initMethod);
                engine.InjectCallInCctor(module, modType, initMethod);
            }
        }

        private int AllocSlot(int tableIdx)
        {
            if (tableAllocIdx[tableIdx] >= TABLE_SIZE) return -1;
            return tablePermutation[tableIdx][tableAllocIdx[tableIdx]++];
        }

        private int EncodeConstants(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            int encoded = 0;

            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode == DnOpCodes.Ldc_I8)
                {
                    long val = (long)il[i].Operand;
                    int hi = (int)(val >> 32);
                    int lo = (int)(val & 0xFFFFFFFFL);

                    var hiInsts = BuildIntRetrieval(hi);
                    var loInsts = BuildIntRetrieval(lo);

                    if (hiInsts != null && loInsts != null)
                    {
                        var replacement = new List<Instruction>();
                        replacement.AddRange(hiInsts);
                        replacement.Add(Instruction.Create(DnOpCodes.Conv_I8));
                        replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, 32));
                        replacement.Add(Instruction.Create(DnOpCodes.Shl));
                        replacement.AddRange(loInsts);

                        replacement.Add(Instruction.Create(DnOpCodes.Conv_U4));
                        replacement.Add(Instruction.Create(DnOpCodes.Conv_U8));
                        replacement.Add(Instruction.Create(DnOpCodes.Or));

                        il[i].OpCode = replacement[0].OpCode;
                        il[i].Operand = replacement[0].Operand;
                        for (int j = 1; j < replacement.Count; j++)
                            il.Insert(i + j, replacement[j]);
                        i += replacement.Count - 1;
                        encoded++;
                    }
                }
                else if (il[i].OpCode == DnOpCodes.Ldc_R4)
                {
                    float fval = (float)il[i].Operand;
                    byte[] fBytes = BitConverter.GetBytes(fval);
                    int ival = BitConverter.ToInt32(fBytes, 0);

                    var insts = BuildIntRetrieval(ival);
                    if (insts != null)
                    {
                        var bitsToSingle = module.Import(
                            typeof(BitConverter).GetMethod("ToSingle", new[] { typeof(byte[]), typeof(int) }));
                        var getBytes = module.Import(
                            typeof(BitConverter).GetMethod("GetBytes", new[] { typeof(int) }));

                        var replacement = new List<Instruction>();
                        replacement.AddRange(insts);
                        replacement.Add(Instruction.Create(DnOpCodes.Call, getBytes));
                        replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                        replacement.Add(Instruction.Create(DnOpCodes.Call, bitsToSingle));

                        il[i].OpCode = replacement[0].OpCode;
                        il[i].Operand = replacement[0].Operand;
                        for (int j = 1; j < replacement.Count; j++)
                            il.Insert(i + j, replacement[j]);
                        i += replacement.Count - 1;
                        encoded++;
                    }
                }
                else if (il[i].OpCode == DnOpCodes.Ldc_R8)
                {
                    double dval = (double)il[i].Operand;
                    byte[] dBytes = BitConverter.GetBytes(dval);
                    int lo = BitConverter.ToInt32(dBytes, 0);
                    int hi = BitConverter.ToInt32(dBytes, 4);

                    var loInsts = BuildIntRetrieval(lo);
                    var hiInsts = BuildIntRetrieval(hi);

                    if (loInsts != null && hiInsts != null)
                    {
                        var int64BitsToDouble = module.Import(
                            typeof(BitConverter).GetMethod("Int64BitsToDouble", new[] { typeof(long) }));

                        var replacement = new List<Instruction>();
                        replacement.AddRange(hiInsts);
                        replacement.Add(Instruction.Create(DnOpCodes.Conv_I8));
                        replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, 32));
                        replacement.Add(Instruction.Create(DnOpCodes.Shl));
                        replacement.AddRange(loInsts);
                        replacement.Add(Instruction.Create(DnOpCodes.Conv_U4));
                        replacement.Add(Instruction.Create(DnOpCodes.Conv_U8));
                        replacement.Add(Instruction.Create(DnOpCodes.Or));
                        replacement.Add(Instruction.Create(DnOpCodes.Call, int64BitsToDouble));

                        il[i].OpCode = replacement[0].OpCode;
                        il[i].Operand = replacement[0].Operand;
                        for (int j = 1; j < replacement.Count; j++)
                            il.Insert(i + j, replacement[j]);
                        i += replacement.Count - 1;
                        encoded++;
                    }
                }
            }

            return encoded;
        }

        private List<Instruction> BuildIntRetrieval(int target)
        {
            int pattern = rng.Next(0, 5);
            switch (pattern)
            {
                case 0: return BuildTableLookup(target);
                case 1: return BuildCrossTableLookup(target);
                case 2: return BuildSeedMath(target);
                case 3: return BuildChainedLookup(target);
                default: return BuildArithmeticChain(target);
            }
        }

        private List<Instruction> BuildTableLookup(int target)
        {

            int mode = rng.Next(0, 4);
            int t = mode;
            int s1 = AllocSlot(t);
            int s2 = AllocSlot(t);
            if (s1 < 0 || s2 < 0) return BuildArithmeticChain(target);

            SetTablePair(t, s1, s2, target, mode);

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s2));
            insts.Add(Instruction.Create(DnOpCodes.Call, decoderMethods[mode]));
            return insts;
        }

        private List<Instruction> BuildCrossTableLookup(int target)
        {

            int modeA = rng.Next(0, 4);
            int modeB = rng.Next(0, 4);
            while (modeB == modeA) modeB = rng.Next(0, 4);
            int tA = modeA;
            int tB = modeB;

            int a1 = AllocSlot(tA); int a2 = AllocSlot(tA);
            int b1 = AllocSlot(tB); int b2 = AllocSlot(tB);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0) return BuildArithmeticChain(target);

            int partial = rng.Next(int.MinValue, int.MaxValue);
            int other = partial ^ target;

            SetTablePair(tA, a1, a2, partial, modeA);
            SetTablePair(tB, b1, b2, other, modeB);

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a2));
            insts.Add(Instruction.Create(DnOpCodes.Call, decoderMethods[modeA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b2));
            insts.Add(Instruction.Create(DnOpCodes.Call, decoderMethods[modeB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildSeedMath(int target)
        {
            int diff = target ^ masterSeedValue;
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, masterSeed));

            int extra = rng.Next(0, 3);
            switch (extra)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterSeedValue - target));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - (~masterSeedValue)));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildChainedLookup(int target)
        {

            int mA = rng.Next(0, 4);
            int mB = rng.Next(0, 4);
            while (mB == mA) mB = rng.Next(0, 4);
            int mC = rng.Next(0, 4);
            while (mC == mA || mC == mB) mC = rng.Next(0, 4);
            int tA = mA;
            int tB = mB;
            int tC = mC;

            int a1 = AllocSlot(tA); int a2 = AllocSlot(tA);
            int b1 = AllocSlot(tB); int b2 = AllocSlot(tB);
            int c1 = AllocSlot(tC); int c2 = AllocSlot(tC);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0 || c1 < 0 || c2 < 0)
                return BuildArithmeticChain(target);

            int p1 = rng.Next(int.MinValue, int.MaxValue);
            int p2 = rng.Next(int.MinValue, int.MaxValue);
            int p3 = target ^ p1 ^ p2;

            SetTablePair(tA, a1, a2, p1, mA);
            SetTablePair(tB, b1, b2, p2, mB);
            SetTablePair(tC, c1, c2, p3, mC);

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a2));
            insts.Add(Instruction.Create(DnOpCodes.Call, decoderMethods[mA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b2));
            insts.Add(Instruction.Create(DnOpCodes.Call, decoderMethods[mB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, c1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, c2));
            insts.Add(Instruction.Create(DnOpCodes.Call, decoderMethods[mC]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private void SetTablePair(int table, int s1, int s2, int target, int mode)
        {
            switch (mode)
            {
                case 0: tableData[table][s2] = tableData[table][s1] ^ target; break;
                case 1: tableData[table][s2] = target - tableData[table][s1]; break;
                case 2: tableData[table][s2] = ~tableData[table][s1] ^ target; break;
                case 3: tableData[table][s2] = target + ~tableData[table][s1]; break;
            }
        }

        private List<Instruction> BuildArithmeticChain(int target)
        {
            var insts = new List<Instruction>();
            int p = rng.Next(0, 8);
            switch (p)
            {
                case 0:
                    int k1 = rng.Next(int.MinValue, int.MaxValue);
                    int k2 = rng.Next(int.MinValue, int.MaxValue);
                    int k3 = rng.Next(int.MinValue, int.MaxValue);
                    int k4 = target ^ k1 ^ k2 ^ k3;
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k2));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k3));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k4));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    int m1 = rng.Next(int.MinValue, int.MaxValue);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, m1));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - (~m1)));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 2:
                    int n1 = rng.Next(1000, 999999);
                    int n2 = rng.Next(1000, 999999);
                    int n3 = target - (n1 + n2);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n2));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, n3));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 3:
                    int mask = rng.Next(int.MinValue, int.MaxValue);
                    int pa = target & mask;
                    int pb = target & ~mask;
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, pa));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, pb));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    break;
                case 4:
                    int r1 = rng.Next(int.MinValue, int.MaxValue);
                    int r2 = rng.Next(int.MinValue, int.MaxValue);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, r1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, r2));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, (r1 + r2) ^ target));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 5:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~target));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    break;
                case 6:
                    int w1 = rng.Next(int.MinValue, int.MaxValue);
                    int w2 = target - w1;
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, w1));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, w2));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                default:
                    int z1 = rng.Next(100000, 9999999);
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, z1 + target));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, z1));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
            }
            return insts;
        }

        private MethodDef BuildDecoderMethod(ModuleDef module, int mode)
        {
            int tableIdx = mode % TABLE_COUNT;
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

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, constTables[tableIdx]));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, constTables[tableIdx]));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            switch (mode % 4)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 3:

                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
            }

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
            var il = method.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDefUser BuildTableInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterSeedValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, masterSeed));

            for (int t = 0; t < TABLE_COUNT; t++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, TABLE_SIZE));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));

                for (int i = 0; i < TABLE_SIZE; i++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(engine.LoadInt(i));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, tableData[t][i]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                }

                il.Add(Instruction.Create(DnOpCodes.Stsfld, constTables[t]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

