using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class PolymorphicNoiseProtection
    {
        private Obfuscation engine;
        private Random rng;
        private FieldDef sharedAnchor;

        internal PolymorphicNoiseProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyPolymorphicNoise(ModuleDef module, TypeDef modType)
        {
            sharedAnchor = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            modType.Fields.Add(sharedAnchor);

            int touched = 0;
            int budget = engine.injectedMethods.Count;

            List<MethodDef> targets = new List<MethodDef>(engine.injectedMethods);
            foreach (MethodDef m in targets)
            {
                if (m == null) continue;
                if (m.IsPinvokeImpl) continue;
                if (!m.HasBody) continue;
                if (m.IsConstructor || m.IsStaticConstructor) continue;
                if (m.Body.Instructions.Count == 0) continue;
                if (m.Body.Instructions.Count > 2000) continue;

                if (BodyContainsCalli(m.Body)) continue;

                try
                {
                    InjectNoise(module, m);
                    touched++;
                    if (touched > 800) break;
                }
                catch { }
            }
        }

        private void InjectNoise(ModuleDef module, MethodDef m)
        {
            var body = m.Body;
            var il = body.Instructions;
            int count = il.Count;
            if (count < 2) return;

            int budget = rng.Next(1, 4);
            for (int b = 0; b < budget; b++)
            {
                int pos = FindSafeInsertPoint(m, il);
                if (pos < 0) break;
                EmitNoiseAtPosition(module, m, il, pos);
            }
        }

        private static bool BodyContainsCalli(CilBody body)
        {
            if (body == null) return false;
            foreach (Instruction ins in body.Instructions)
            {
                if (ins.OpCode.Code == Code.Calli) return true;
            }
            return false;
        }

        private int FindSafeInsertPoint(MethodDef m, IList<Instruction> il)
        {
            int attempts = 5;
            while (attempts-- > 0)
            {
                int pos = rng.Next(0, il.Count);
                if (pos == 0) continue;
                Instruction at = il[pos];
                if (IsUnsafeOpcode(at)) continue;
                if (m.Body.HasExceptionHandlers && IsHandlerBoundary(m, at)) continue;
                if (pos + 1 < il.Count && IsBranchTarget(il, at)) { }
                return pos;
            }
            return -1;
        }

        private bool IsUnsafeOpcode(Instruction inst)
        {
            Code c = inst.OpCode.Code;
            if (c == Code.Ret || c == Code.Throw || c == Code.Rethrow) return true;
            if (c == Code.Leave || c == Code.Leave_S) return true;
            if (c == Code.Endfilter || c == Code.Endfinally) return true;
            if (c == Code.Jmp) return true;
            return false;
        }

        private bool IsHandlerBoundary(MethodDef m, Instruction at)
        {
            foreach (var eh in m.Body.ExceptionHandlers)
            {
                if (at == eh.TryStart || at == eh.TryEnd ||
                    at == eh.HandlerStart || at == eh.HandlerEnd ||
                    at == eh.FilterStart)
                    return true;
            }
            return false;
        }

        private bool IsBranchTarget(IList<Instruction> il, Instruction at)
        {
            if (il == null || at == null) return false;
            for (int i = 0; i < il.Count; i++)
            {
                var ins = il[i];
                var ot = ins.OpCode.OperandType;
                if (ot == OperandType.InlineBrTarget || ot == OperandType.ShortInlineBrTarget)
                {
                    if (ReferenceEquals(ins.Operand, at)) return true;
                }
                else if (ot == OperandType.InlineSwitch)
                {
                    var arr = ins.Operand as Instruction[];
                    if (arr != null)
                    {
                        for (int k = 0; k < arr.Length; k++)
                            if (ReferenceEquals(arr[k], at)) return true;
                    }
                }
            }
            return false;
        }

        private void EmitNoiseAtPosition(ModuleDef module, MethodDef m, IList<Instruction> il, int pos)
        {
            int kind = rng.Next(5);
            switch (kind)
            {
                case 0: EmitOpaqueAnchorRead(module, il, pos); break;
                case 1: EmitVolatileTouch(module, il, pos); break;
                case 2: EmitDeadBranch(module, m, il, pos); break;
                case 3: EmitArithmeticNoise(module, il, pos); break;
                case 4: EmitStringNoiseLoad(module, il, pos); break;
            }
        }

        private void EmitOpaqueAnchorRead(ModuleDef module, IList<Instruction> il, int pos)
        {
            il.Insert(pos, Instruction.Create(DnOpCodes.Ldsfld, sharedAnchor));
            il.Insert(pos + 1, Instruction.Create(DnOpCodes.Pop));
        }

        private void EmitVolatileTouch(ModuleDef module, IList<Instruction> il, int pos)
        {
            il.Insert(pos, Instruction.Create(DnOpCodes.Ldsfld, sharedAnchor));
            il.Insert(pos + 1, Instruction.Create(DnOpCodes.Ldc_I4, NextNonZero()));
            il.Insert(pos + 2, Instruction.Create(DnOpCodes.Xor));
            il.Insert(pos + 3, Instruction.Create(DnOpCodes.Pop));
        }

        private void EmitDeadBranch(ModuleDef module, MethodDef m, IList<Instruction> il, int pos)
        {
            int seed = NextNonZero();
            Instruction target = il[pos];

            il.Insert(pos, Instruction.Create(DnOpCodes.Ldc_I4, seed));
            il.Insert(pos + 1, Instruction.Create(DnOpCodes.Ldc_I4, seed));
            il.Insert(pos + 2, Instruction.Create(DnOpCodes.Beq, target));
        }

        private void EmitArithmeticNoise(ModuleDef module, IList<Instruction> il, int pos)
        {
            int a = rng.Next();
            int b = rng.Next();
            il.Insert(pos, Instruction.Create(DnOpCodes.Ldc_I4, a));
            il.Insert(pos + 1, Instruction.Create(DnOpCodes.Ldc_I4, b));
            int op = rng.Next(3);
            switch (op)
            {
                case 0: il.Insert(pos + 2, Instruction.Create(DnOpCodes.Add)); break;
                case 1: il.Insert(pos + 2, Instruction.Create(DnOpCodes.Xor)); break;
                case 2: il.Insert(pos + 2, Instruction.Create(DnOpCodes.Or)); break;
            }
            il.Insert(pos + 3, Instruction.Create(DnOpCodes.Pop));
        }

        private void EmitStringNoiseLoad(ModuleDef module, IList<Instruction> il, int pos)
        {
            byte[] junk = engine.CryptoRandom(rng.Next(6, 24));
            string fake = Convert.ToBase64String(junk);
            il.Insert(pos, Instruction.Create(DnOpCodes.Ldstr, fake));
            il.Insert(pos + 1, Instruction.Create(DnOpCodes.Pop));
        }

        private int NextNonZero()
        {
            int v;
            do { v = rng.Next(); } while (v == 0);
            return v;
        }
    }
}

