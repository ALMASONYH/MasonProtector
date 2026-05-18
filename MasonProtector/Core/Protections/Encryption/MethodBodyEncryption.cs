using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class MethodBodyEncryptionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int ARRAY_POOL_SIZE = 16;
        private const int ARRAY_ELEMENT_COUNT = 256;
        private List<FieldDef> encArrayFields;
        private List<int[]> encArrayData;
        private List<int[]> encArrayShuffles;
        private int[] encArrayPtrs;
        private TypeDef encContainerType;
        private List<MethodDef> resolverMethods;
        private List<FieldDef> xorKeyFields;
        private int[] xorKeyValues;

        internal MethodBodyEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyMethodBodyEncryption(ModuleDef module, TypeDef modType)
        {
            encArrayFields = new List<FieldDef>();
            encArrayData = new List<int[]>();
            encArrayShuffles = new List<int[]>();
            encArrayPtrs = new int[ARRAY_POOL_SIZE];
            resolverMethods = new List<MethodDef>();
            xorKeyFields = new List<FieldDef>();
            xorKeyValues = new int[12];

            encContainerType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            encContainerType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(encContainerType);
            engine.injectedTypes.Add(encContainerType);

            for (int k = 0; k < 12; k++)
            {
                xorKeyValues[k] = rng.Next(100000, int.MaxValue / 2);
                var kf = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                encContainerType.Fields.Add(kf);
                xorKeyFields.Add(kf);
            }

            for (int a = 0; a < ARRAY_POOL_SIZE; a++)
            {
                var arrField = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                encContainerType.Fields.Add(arrField);
                encArrayFields.Add(arrField);

                var data = new int[ARRAY_ELEMENT_COUNT];
                for (int i = 0; i < ARRAY_ELEMENT_COUNT; i++)
                    data[i] = rng.Next(int.MinValue, int.MaxValue);
                encArrayData.Add(data);

                var shuffle = new int[ARRAY_ELEMENT_COUNT];
                for (int i = 0; i < ARRAY_ELEMENT_COUNT; i++) shuffle[i] = i;
                for (int i = ARRAY_ELEMENT_COUNT - 1; i > 0; i--)
                {
                    int j = rng.Next(0, i + 1);
                    int tmp = shuffle[i]; shuffle[i] = shuffle[j]; shuffle[j] = tmp;
                }
                encArrayShuffles.Add(shuffle);
                encArrayPtrs[a] = 0;
            }

            for (int d = 0; d < rng.Next(4, 8); d++)
            {
                encContainerType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }

            for (int r = 0; r < 6; r++)
            {
                var resolver = BuildResolverMethod(module, r);
                encContainerType.Methods.Add(resolver);
                engine.injectedMethods.Add(resolver);
                resolverMethods.Add(resolver);
            }

            for (int f = 0; f < 4; f++)
            {
                var fake = BuildFakeResolver(module);
                encContainerType.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }

            int counter = 0;

            bool allowDesigner = engine.cfg != null && engine.cfg.MaximumEncryption;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                if (type.HasGenericParameters) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method, allowDesigner)) continue;
                    try
                    {
                        counter += EncryptMethodBody(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            if (counter > 0)
            {
                var initMethod = BuildEncArrayInitializer(module);
                encContainerType.Methods.Add(initMethod);
                engine.injectedMethods.Add(initMethod);
                engine.InjectCallInCctor(module, modType, initMethod);
            }
        }

        private int AllocSlot(int arrayIdx)
        {
            if (encArrayPtrs[arrayIdx] >= ARRAY_ELEMENT_COUNT) return -1;
            return encArrayShuffles[arrayIdx][encArrayPtrs[arrayIdx]++];
        }

        private int EncryptMethodBody(ModuleDef module, MethodDef method)
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

                int pattern = rng.Next(0, 5);
                List<Instruction> replacement = null;

                switch (pattern)
                {
                    case 0: replacement = BuildArrayXorRetrieval(val); break;
                    case 1: replacement = BuildDoubleArrayRetrieval(val); break;
                    case 2: replacement = BuildKeyFieldRetrieval(val); break;
                    case 3: replacement = BuildTripleArrayRetrieval(val); break;
                    default: replacement = BuildResolverRetrieval(val); break;
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

        private List<Instruction> BuildArrayXorRetrieval(int target)
        {
            int a = rng.Next(0, ARRAY_POOL_SIZE);
            int s1 = AllocSlot(a);
            int s2 = AllocSlot(a);
            if (s1 < 0 || s2 < 0) return BuildFallbackRetrieval(target);

            encArrayData[a][s2] = encArrayData[a][s1] ^ target;

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[a]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[a]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildDoubleArrayRetrieval(int target)
        {
            int aA = rng.Next(0, ARRAY_POOL_SIZE);
            int aB = rng.Next(0, ARRAY_POOL_SIZE);
            while (aB == aA) aB = rng.Next(0, ARRAY_POOL_SIZE);

            int sa1 = AllocSlot(aA); int sa2 = AllocSlot(aA);
            int sb1 = AllocSlot(aB); int sb2 = AllocSlot(aB);
            if (sa1 < 0 || sa2 < 0 || sb1 < 0 || sb2 < 0) return BuildFallbackRetrieval(target);

            int partial = rng.Next(int.MinValue, int.MaxValue);
            int other = partial ^ target;

            encArrayData[aA][sa2] = encArrayData[aA][sa1] ^ partial;
            encArrayData[aB][sb2] = encArrayData[aB][sb1] ^ other;

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sa1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sa2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));

            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sb1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sb2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));

            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildKeyFieldRetrieval(int target)
        {
            int kIdx = rng.Next(0, 12);
            int diff = target ^ xorKeyValues[kIdx];

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, xorKeyFields[kIdx]));

            int pattern = rng.Next(0, 3);
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, target - (~xorKeyValues[kIdx])));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, xorKeyValues[kIdx] - target));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildTripleArrayRetrieval(int target)
        {
            int aA = rng.Next(0, ARRAY_POOL_SIZE);
            int aB = rng.Next(0, ARRAY_POOL_SIZE);
            while (aB == aA) aB = rng.Next(0, ARRAY_POOL_SIZE);
            int aC = rng.Next(0, ARRAY_POOL_SIZE);
            while (aC == aA || aC == aB) aC = rng.Next(0, ARRAY_POOL_SIZE);

            int sa1 = AllocSlot(aA); int sa2 = AllocSlot(aA);
            int sb1 = AllocSlot(aB); int sb2 = AllocSlot(aB);
            int sc1 = AllocSlot(aC); int sc2 = AllocSlot(aC);
            if (sa1 < 0 || sa2 < 0 || sb1 < 0 || sb2 < 0 || sc1 < 0 || sc2 < 0)
                return BuildFallbackRetrieval(target);

            int p1 = rng.Next(int.MinValue, int.MaxValue);
            int p2 = rng.Next(int.MinValue, int.MaxValue);
            int p3 = target ^ p1 ^ p2;

            encArrayData[aA][sa2] = encArrayData[aA][sa1] ^ p1;
            encArrayData[aB][sb2] = encArrayData[aB][sb1] ^ p2;
            encArrayData[aC][sc2] = encArrayData[aC][sc1] ^ p3;

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sa1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sa2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));

            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sb1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aB]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sb2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Xor));

            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aC]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sc1));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[aC]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sc2));
            insts.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildResolverRetrieval(int target)
        {
            int a = rng.Next(0, ARRAY_POOL_SIZE);
            int s1 = AllocSlot(a); int s2 = AllocSlot(a);
            if (s1 < 0 || s2 < 0) return BuildFallbackRetrieval(target);

            int rIdx = rng.Next(0, resolverMethods.Count);
            int mode = rIdx % 3;

            switch (mode)
            {
                case 0: encArrayData[a][s2] = encArrayData[a][s1] ^ target; break;
                case 1: encArrayData[a][s2] = target - encArrayData[a][s1]; break;
                case 2: encArrayData[a][s2] = ~encArrayData[a][s1] ^ target; break;
            }

            var insts = new List<Instruction>();
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s1));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, s2));
            insts.Add(Instruction.Create(DnOpCodes.Call, resolverMethods[rIdx]));
            return insts;
        }

        private List<Instruction> BuildFallbackRetrieval(int target)
        {
            var insts = new List<Instruction>();
            int k = rng.Next(int.MinValue, int.MaxValue);
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ target));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private MethodDef BuildResolverMethod(ModuleDef module, int variant)
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
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, ARRAY_POOL_SIZE));
            il.Add(Instruction.Create(DnOpCodes.Rem));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int a = 0; a < ARRAY_POOL_SIZE; a++)
            {
                var nextCheck = Instruction.Create(DnOpCodes.Nop);
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                il.Add(Instruction.Create(DnOpCodes.Bne_Un, nextCheck));

                il.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[a]));
                il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
                il.Add(Instruction.Create(DnOpCodes.Stloc_1));

                il.Add(Instruction.Create(DnOpCodes.Ldsfld, encArrayFields[a]));
                il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));

                switch (variant % 3)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        break;
                    case 1:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        break;
                }

                il.Add(Instruction.Create(DnOpCodes.Ret));
                il.Add(nextCheck);
            }

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildFakeResolver(ModuleDef module)
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
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDefUser BuildEncArrayInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            for (int k = 0; k < 12; k++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, xorKeyValues[k]));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, xorKeyFields[k]));
            }

            for (int a = 0; a < ARRAY_POOL_SIZE; a++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, ARRAY_ELEMENT_COUNT));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));

                for (int i = 0; i < ARRAY_ELEMENT_COUNT; i++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(engine.LoadInt(i));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, encArrayData[a][i]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                }

                il.Add(Instruction.Create(DnOpCodes.Stsfld, encArrayFields[a]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

