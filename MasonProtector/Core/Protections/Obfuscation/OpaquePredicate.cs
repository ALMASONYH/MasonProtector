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
    internal class OpaquePredicateProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int PREDICATE_FIELD_COUNT = 48;
        private List<FieldDef> predicateFields;
        private int[] predicateValues;
        private TypeDef predicateHost;
        private List<MethodDef> evaluatorMethods;

        internal OpaquePredicateProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyOpaquePredicates(ModuleDef module, TypeDef modType)
        {
            predicateFields = new List<FieldDef>();
            predicateValues = new int[PREDICATE_FIELD_COUNT];
            evaluatorMethods = new List<MethodDef>();

            predicateHost = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            predicateHost.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(predicateHost);
            engine.injectedTypes.Add(predicateHost);

            for (int i = 0; i < PREDICATE_FIELD_COUNT; i++)
            {
                predicateValues[i] = rng.Next(1000, int.MaxValue / 2);
                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                predicateHost.Fields.Add(field);
                predicateFields.Add(field);
            }

            for (int d = 0; d < rng.Next(10, 24); d++)
            {
                predicateHost.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }

            for (int e = 0; e < 36; e++)
            {
                var eval = BuildEvaluatorMethod(module, e);
                predicateHost.Methods.Add(eval);
                engine.injectedMethods.Add(eval);
                evaluatorMethods.Add(eval);
            }

            for (int f = 0; f < 24; f++)
            {
                var fake = BuildFakeEvaluator(module);
                predicateHost.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (engine.controlFlowFlattenedMethods.Contains(method)) continue;
                    if (method.IsConstructor || method.IsStaticConstructor) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (engine.injectedTypes.Contains(type)) continue;
                    if (method.Body.Instructions.Count < 6) continue;
                    try
                    {
                        InjectOpaquePredicates(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            var initMethod = BuildPredicateInitializer(module);
            predicateHost.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);
            engine.InjectCallInCctor(module, modType, initMethod);
        }

        private static bool LeavesStackAtBaseline(Instruction inst)
        {
            Code c = inst.OpCode.Code;
            switch (c)
            {
                case Code.Nop:
                case Code.Pop:
                case Code.Stloc_0:
                case Code.Stloc_1:
                case Code.Stloc_2:
                case Code.Stloc_3:
                case Code.Stloc:
                case Code.Stloc_S:
                case Code.Stsfld:
                case Code.Stfld:
                case Code.Stelem:
                case Code.Stelem_I:
                case Code.Stelem_I1:
                case Code.Stelem_I2:
                case Code.Stelem_I4:
                case Code.Stelem_I8:
                case Code.Stelem_R4:
                case Code.Stelem_R8:
                case Code.Stelem_Ref:
                case Code.Stind_I:
                case Code.Stind_I1:
                case Code.Stind_I2:
                case Code.Stind_I4:
                case Code.Stind_I8:
                case Code.Stind_R4:
                case Code.Stind_R8:
                case Code.Stind_Ref:
                case Code.Starg:
                case Code.Starg_S:
                case Code.Stobj:
                    return true;
                case Code.Call:
                case Code.Callvirt:
                {
                    var m = inst.Operand as IMethod;
                    if (m == null || m.MethodSig == null) return false;
                    var rt = m.MethodSig.RetType;
                    return rt != null && rt.FullName == "System.Void";
                }
            }
            return false;
        }

        private void InjectOpaquePredicates(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            int injectCount = Math.Min(il.Count / 6, 15);

            var safePositions = FindSafeInsertPositions(il, method.Body.ExceptionHandlers);
            if (safePositions.Count == 0) return;

            for (int n = 0; n < injectCount && safePositions.Count > 0; n++)
            {
                int posIdx = rng.Next(0, safePositions.Count);
                int pos = safePositions[posIdx];
                safePositions.RemoveAt(posIdx);

                if (pos >= il.Count) continue;

                var target = il[pos];
                int predicateType = rng.Next(0, 8);
                var newInsts = new List<Instruction>();

                int predicate11 = rng.Next(0, 11);
                switch (predicate11)
                {
                    case 0:
                        newInsts.AddRange(BuildAlwaysTruePredicate(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        break;
                    case 1:
                        newInsts.AddRange(BuildAlwaysFalsePredicate(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        newInsts.AddRange(BuildDeadCode(module));
                        break;
                    case 2:
                        newInsts.AddRange(BuildFieldComparisonPredicate(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        break;
                    case 3:
                        newInsts.AddRange(BuildMathInvariant(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        break;
                    case 4:
                        newInsts.AddRange(BuildXorChainPredicate(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brfalse, target));
                        break;
                    case 5:
                        newInsts.AddRange(BuildModuloPredicate(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        break;
                    case 6:
                        newInsts.AddRange(BuildBitwisePredicate(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        break;
                    case 7:
                        newInsts.AddRange(BuildMbaAlwaysTrue(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        break;
                    case 8:
                        newInsts.AddRange(BuildMbaAlwaysFalse(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        newInsts.AddRange(BuildDeadCode(module));
                        break;
                    case 9:
                        newInsts.AddRange(BuildMbaIdentityCompare(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        break;
                    default:
                        newInsts.AddRange(BuildEvaluatorPredicate(module));
                        newInsts.Add(Instruction.Create(DnOpCodes.Brtrue, target));
                        break;
                }

                for (int i = newInsts.Count - 1; i >= 0; i--)
                    il.Insert(pos, newInsts[i]);

                for (int i = 0; i < safePositions.Count; i++)
                {
                    if (safePositions[i] >= pos)
                        safePositions[i] += newInsts.Count;
                }
            }
        }

        private List<int> FindSafeInsertPositions(IList<Instruction> il, IList<ExceptionHandler> ehs)
        {
            var positions = new List<int>();
            if (il.Count < 2) return positions;

            var forbidden = new HashSet<Instruction>();
            for (int i = 0; i < il.Count; i++)
            {
                var op = il[i].OpCode;
                if (op.OperandType == OperandType.InlineBrTarget ||
                    op.OperandType == OperandType.ShortInlineBrTarget)
                {
                    var t = il[i].Operand as Instruction;
                    if (t != null) forbidden.Add(t);
                }
                else if (op.OperandType == OperandType.InlineSwitch)
                {
                    var ts = il[i].Operand as Instruction[];
                    if (ts != null)
                        foreach (var t in ts) if (t != null) forbidden.Add(t);
                }
            }
            if (ehs != null)
            {
                foreach (var eh in ehs)
                {
                    if (eh.TryStart     != null) forbidden.Add(eh.TryStart);
                    if (eh.TryEnd       != null) forbidden.Add(eh.TryEnd);
                    if (eh.HandlerStart != null) forbidden.Add(eh.HandlerStart);
                    if (eh.HandlerEnd   != null) forbidden.Add(eh.HandlerEnd);
                    if (eh.FilterStart  != null) forbidden.Add(eh.FilterStart);
                }
            }

            for (int i = 1; i < il.Count; i++)
            {
                var cur = il[i];
                if (cur.OpCode == DnOpCodes.Ret ||
                    cur.OpCode == DnOpCodes.Throw ||
                    cur.OpCode == DnOpCodes.Rethrow) continue;
                if (cur.OpCode.FlowControl == FlowControl.Branch ||
                    cur.OpCode.FlowControl == FlowControl.Cond_Branch) continue;
                if (forbidden.Contains(cur)) continue;

                if (!LeavesStackAtBaseline(il[i - 1])) continue;

                positions.Add(i);
            }
            return positions;
        }

        private List<Instruction> BuildAlwaysTruePredicate(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idx = rng.Next(0, PREDICATE_FIELD_COUNT);
            int val = predicateValues[idx];

            int pattern = rng.Next(0, 4);
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
                case 2:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    insts.Add(Instruction.Create(DnOpCodes.Cgt));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    insts.Add(Instruction.Create(DnOpCodes.Cgt));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildAlwaysFalsePredicate(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idxA = rng.Next(0, PREDICATE_FIELD_COUNT);
            int idxB = rng.Next(0, PREDICATE_FIELD_COUNT);
            while (idxB == idxA) idxB = rng.Next(0, PREDICATE_FIELD_COUNT);

            int pattern = rng.Next(0, 3);
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildFieldComparisonPredicate(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idxA = rng.Next(0, PREDICATE_FIELD_COUNT);
            int idxB = rng.Next(0, PREDICATE_FIELD_COUNT);
            while (idxB == idxA) idxB = rng.Next(0, PREDICATE_FIELD_COUNT);

            int valA = predicateValues[idxA];
            int valB = predicateValues[idxB];
            int sum = valA + valB;

            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxB]));
            insts.Add(Instruction.Create(DnOpCodes.Add));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, sum));
            insts.Add(Instruction.Create(DnOpCodes.Ceq));
            return insts;
        }

        private List<Instruction> BuildMathInvariant(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idx = rng.Next(0, PREDICATE_FIELD_COUNT);
            int val = predicateValues[idx];

            int pattern = rng.Next(0, 4);
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Mul));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    insts.Add(Instruction.Create(DnOpCodes.Cgt));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
                    insts.Add(Instruction.Create(DnOpCodes.Mul));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Cgt));
                    break;
                case 2:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
                    insts.Add(Instruction.Create(DnOpCodes.Cgt));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildXorChainPredicate(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idxA = rng.Next(0, PREDICATE_FIELD_COUNT);
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            return insts;
        }

        private List<Instruction> BuildModuloPredicate(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idx = rng.Next(0, PREDICATE_FIELD_COUNT);
            int val = predicateValues[idx];
            int mod = rng.Next(2, 100);
            int expected = val % mod;

            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idx]));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, mod));
            insts.Add(Instruction.Create(DnOpCodes.Rem));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, expected));
            insts.Add(Instruction.Create(DnOpCodes.Ceq));
            return insts;
        }

        private List<Instruction> BuildBitwisePredicate(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idxA = rng.Next(0, PREDICATE_FIELD_COUNT);
            int idxB = rng.Next(0, PREDICATE_FIELD_COUNT);
            while (idxB == idxA) idxB = rng.Next(0, PREDICATE_FIELD_COUNT);

            int valA = predicateValues[idxA];
            int valB = predicateValues[idxB];
            int expected = (valA | valB) & (valA ^ valB);

            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxB]));
            insts.Add(Instruction.Create(DnOpCodes.Or));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxA]));
            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxB]));
            insts.Add(Instruction.Create(DnOpCodes.Xor));
            insts.Add(Instruction.Create(DnOpCodes.And));
            insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, expected));
            insts.Add(Instruction.Create(DnOpCodes.Ceq));
            return insts;
        }

        private List<Instruction> BuildMbaAlwaysTrue(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idxX = rng.Next(0, PREDICATE_FIELD_COUNT);
            int idxY = rng.Next(0, PREDICATE_FIELD_COUNT);
            while (idxY == idxX) idxY = rng.Next(0, PREDICATE_FIELD_COUNT);

            int variant = rng.Next(0, 4);
            switch (variant)
            {
                case 0:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
                    insts.Add(Instruction.Create(DnOpCodes.Mul));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
                case 1:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
                case 2:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
                    insts.Add(Instruction.Create(DnOpCodes.Mul));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
                default:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
                    insts.Add(Instruction.Create(DnOpCodes.Mul));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildMbaAlwaysFalse(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idxX = rng.Next(0, PREDICATE_FIELD_COUNT);
            int idxY = rng.Next(0, PREDICATE_FIELD_COUNT);
            while (idxY == idxX) idxY = rng.Next(0, PREDICATE_FIELD_COUNT);

            int variant = rng.Next(0, 3);
            switch (variant)
            {
                case 0:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                case 1:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    break;
                default:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildMbaIdentityCompare(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int idxX = rng.Next(0, PREDICATE_FIELD_COUNT);
            int idxY = rng.Next(0, PREDICATE_FIELD_COUNT);
            while (idxY == idxX) idxY = rng.Next(0, PREDICATE_FIELD_COUNT);

            int variant = rng.Next(0, 3);
            switch (variant)
            {
                case 0:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Not));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
                case 1:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
                default:

                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.And));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Or));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxX]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[idxY]));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Sub));
                    insts.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
            }
            return insts;
        }

        private List<Instruction> BuildEvaluatorPredicate(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int evalIdx = rng.Next(0, evaluatorMethods.Count);
            int fieldIdx = rng.Next(0, PREDICATE_FIELD_COUNT);

            insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[fieldIdx]));
            insts.Add(Instruction.Create(DnOpCodes.Call, evaluatorMethods[evalIdx]));
            return insts;
        }

        private List<Instruction> BuildDeadCode(ModuleDef module)
        {
            var insts = new List<Instruction>();
            int pattern = rng.Next(0, 4);
            switch (pattern)
            {
                case 0:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    insts.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 1:
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 2:
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, predicateFields[rng.Next(0, PREDICATE_FIELD_COUNT)]));
                    insts.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                default:
                    insts.Add(Instruction.Create(DnOpCodes.Nop));
                    break;
            }
            return insts;
        }

        private MethodDef BuildEvaluatorMethod(ModuleDef module, int variant)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            switch (variant % 6)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Mul));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Cgt));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Cgt));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Or));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
            }

            return method;
        }

        private MethodDef BuildFakeEvaluator(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDefUser BuildPredicateInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            for (int i = 0; i < PREDICATE_FIELD_COUNT; i++)
            {
                int pattern = rng.Next(0, 4);
                switch (pattern)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, predicateValues[i]));
                        break;
                    case 1:
                        int k = rng.Next(int.MinValue, int.MaxValue);
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ predicateValues[i]));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~predicateValues[i]));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        break;
                    default:
                        int a = rng.Next(1000, 999999);
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a - predicateValues[i]));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        break;
                }
                il.Add(Instruction.Create(DnOpCodes.Stsfld, predicateFields[i]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

