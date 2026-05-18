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
    internal class CrossReferenceEncryptionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int XREF_TABLE_COUNT = 14;
        private const int XREF_TABLE_SIZE = 320;
        private List<TypeDef> xrefHosts;
        private List<FieldDef> xrefTables;
        private List<int[]> xrefData;
        private List<int[]> xrefPermutations;
        private int[] xrefAllocPtrs;
        private List<List<MethodDef>> xrefResolvers;
        private FieldDef chainField;
        private int chainValue;

        internal CrossReferenceEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyCrossReferenceEncryption(ModuleDef module, TypeDef modType)
        {
            xrefHosts = new List<TypeDef>();
            xrefTables = new List<FieldDef>();
            xrefData = new List<int[]>();
            xrefPermutations = new List<int[]>();
            xrefAllocPtrs = new int[XREF_TABLE_COUNT];
            xrefResolvers = new List<List<MethodDef>>();

            for (int t = 0; t < XREF_TABLE_COUNT; t++)
            {
                var host = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(host);
                engine.injectedTypes.Add(host);
                xrefHosts.Add(host);

                var tableField = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(tableField);
                xrefTables.Add(tableField);

                for (int d = 0; d < rng.Next(2, 5); d++)
                {
                    host.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                var data = new int[XREF_TABLE_SIZE];
                for (int i = 0; i < XREF_TABLE_SIZE; i++)
                    data[i] = rng.Next(int.MinValue, int.MaxValue);
                xrefData.Add(data);

                var perm = new int[XREF_TABLE_SIZE];
                for (int i = 0; i < XREF_TABLE_SIZE; i++) perm[i] = i;
                for (int i = XREF_TABLE_SIZE - 1; i > 0; i--)
                {
                    int j = rng.Next(0, i + 1);
                    int tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
                }
                xrefPermutations.Add(perm);
                xrefAllocPtrs[t] = 0;

                var resolvers = new List<MethodDef>();
                for (int r = 0; r < 4; r++)
                {
                    var resolver = BuildXrefResolver(module, tableField, r);
                    host.Methods.Add(resolver);
                    engine.injectedMethods.Add(resolver);
                    resolvers.Add(resolver);
                }
                xrefResolvers.Add(resolvers);

                for (int f = 0; f < 2; f++)
                {
                    var fake = BuildFakeXrefResolver(module);
                    host.Methods.Add(fake);
                    engine.injectedMethods.Add(fake);
                }
            }

            chainValue = rng.Next(100000, int.MaxValue / 2);
            chainField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            xrefHosts[0].Fields.Add(chainField);

            int counter = 0;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    try
                    {
                        counter += EncryptCrossReferences(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            if (counter > 0)
            {
                var initMethod = BuildXrefInitializer(module);
                xrefHosts[0].Methods.Add(initMethod);
                engine.injectedMethods.Add(initMethod);
                engine.InjectCallInCctor(module, modType, initMethod);
            }
        }

        private int AllocSlot(int tableIdx)
        {
            if (xrefAllocPtrs[tableIdx] >= XREF_TABLE_SIZE) return -1;
            return xrefPermutations[tableIdx][xrefAllocPtrs[tableIdx]++];
        }

        private int EncryptCrossReferences(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            int encrypted = 0;

            for (int i = 0; i < il.Count; i++)
            {
                if (!engine.IsIntLoad(il[i])) continue;
                int val = engine.ExtractInt(il[i]);
                if (val == int.MinValue) continue;
                if (val >= -1 && val <= 8) continue;
                if (rng.Next(0, 3) != 0) continue;

                int pattern = rng.Next(0, 4);
                List<Instruction> replacement = null;

                switch (pattern)
                {
                    case 0: replacement = BuildSingleTableLookup(val); break;
                    case 1: replacement = BuildCrossTableLookup(val); break;
                    case 2: replacement = BuildChainedLookup(val); break;
                    default: replacement = BuildChainFieldLookup(val); break;
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

        private List<Instruction> BuildSingleTableLookup(int target)
        {
            int t = rng.Next(0, XREF_TABLE_COUNT);
            int s1 = AllocSlot(t); int s2 = AllocSlot(t);
            if (s1 < 0 || s2 < 0) return BuildFallback(target);

            int mode = rng.Next(0, 4);
            SetPair(t, s1, s2, target, mode);

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s2));
            insts.Add(Instruction.Create(DnOpCodes.Call, xrefResolvers[t][mode]));
            return insts;
        }

        private List<Instruction> BuildCrossTableLookup(int target)
        {
            int tA = rng.Next(0, XREF_TABLE_COUNT);
            int tB = rng.Next(0, XREF_TABLE_COUNT);
            while (tB == tA) tB = rng.Next(0, XREF_TABLE_COUNT);

            int a1 = AllocSlot(tA); int a2 = AllocSlot(tA);
            int b1 = AllocSlot(tB); int b2 = AllocSlot(tB);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0) return BuildFallback(target);

            int partial = rng.Next(int.MinValue, int.MaxValue);
            int other = partial ^ target;

            int mA = rng.Next(0, 4); int mB = rng.Next(0, 4);
            SetPair(tA, a1, a2, partial, mA);
            SetPair(tB, b1, b2, other, mB);

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a2));
            insts.Add(Instruction.Create(DnOpCodes.Call, xrefResolvers[tA][mA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b2));
            insts.Add(Instruction.Create(DnOpCodes.Call, xrefResolvers[tB][mB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildChainedLookup(int target)
        {
            int tA = rng.Next(0, XREF_TABLE_COUNT);
            int tB = rng.Next(0, XREF_TABLE_COUNT);
            while (tB == tA) tB = rng.Next(0, XREF_TABLE_COUNT);
            int tC = rng.Next(0, XREF_TABLE_COUNT);
            while (tC == tA || tC == tB) tC = rng.Next(0, XREF_TABLE_COUNT);

            int a1 = AllocSlot(tA); int a2 = AllocSlot(tA);
            int b1 = AllocSlot(tB); int b2 = AllocSlot(tB);
            int c1 = AllocSlot(tC); int c2 = AllocSlot(tC);
            if (a1 < 0 || a2 < 0 || b1 < 0 || b2 < 0 || c1 < 0 || c2 < 0)
                return BuildFallback(target);

            int p1 = rng.Next(int.MinValue, int.MaxValue);
            int p2 = rng.Next(int.MinValue, int.MaxValue);
            int p3 = target ^ p1 ^ p2;

            int mA = rng.Next(0, 4); int mB = rng.Next(0, 4); int mC = rng.Next(0, 4);
            SetPair(tA, a1, a2, p1, mA);
            SetPair(tB, b1, b2, p2, mB);
            SetPair(tC, c1, c2, p3, mC);

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a2));
            insts.Add(Instruction.Create(DnOpCodes.Call, xrefResolvers[tA][mA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, b2));
            insts.Add(Instruction.Create(DnOpCodes.Call, xrefResolvers[tB][mB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, c1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, c2));
            insts.Add(Instruction.Create(DnOpCodes.Call, xrefResolvers[tC][mC]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildChainFieldLookup(int target)
        {
            int diff = target ^ chainValue;
            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, chainField));

            int pattern = rng.Next(0, 3);
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - (~chainValue)));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, chainValue - target));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
            }
            return insts;
        }

        private void SetPair(int table, int s1, int s2, int target, int mode)
        {
            switch (mode)
            {
                case 0: xrefData[table][s2] = xrefData[table][s1] ^ target; break;
                case 1: xrefData[table][s2] = target - xrefData[table][s1]; break;
                case 2: xrefData[table][s2] = ~xrefData[table][s1] ^ target; break;
                case 3: xrefData[table][s2] = target - (~xrefData[table][s1]); break;
            }
        }

        private List<Instruction> BuildFallback(int target)
        {
            var insts = new List<Instruction>();
            int k = rng.Next(int.MinValue, int.MaxValue);
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ target));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private MethodDef BuildXrefResolver(ModuleDef module, FieldDef tableField, int mode)
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

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, tableField));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, tableField));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            switch (mode)
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
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    break;
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildFakeXrefResolver(ModuleDef module)
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

        private MethodDefUser BuildXrefInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, chainValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, chainField));

            for (int t = 0; t < XREF_TABLE_COUNT; t++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, XREF_TABLE_SIZE));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));

                for (int i = 0; i < XREF_TABLE_SIZE; i++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(engine.LoadInt(i));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, xrefData[t][i]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                }

                il.Add(Instruction.Create(DnOpCodes.Stsfld, xrefTables[t]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

