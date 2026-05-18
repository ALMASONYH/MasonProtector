using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class CctorScramblerProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal CctorScramblerProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal int ApplyCctorScrambler(ModuleDef module)
        {

            TypeDef moduleType = module.GlobalType;
            if (moduleType == null) return 0;
            MethodDef cctor = moduleType.FindStaticConstructor();
            if (cctor == null || cctor.Body == null) return 0;

            var ins = cctor.Body.Instructions;
            if (ins.Count < 2) return 0;

            var realCalls = new List<Instruction>();
            foreach (var i in ins)
            {
                if (i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt)
                {
                    if (i.Operand is IMethod) realCalls.Add(i);
                }
            }
            if (realCalls.Count < 2) return 0;

            const int K_FLAGS = 6;
            FieldDef[] flagFields = new FieldDef[K_FLAGS];
            int[] flagValues = new int[K_FLAGS];
            for (int i = 0; i < K_FLAGS; i++)
            {
                flagFields[i] = BuildOpaqueFlag(module, moduleType);

                int v;
                do { v = rng.Next(int.MinValue, int.MaxValue); } while (v == 0);
                flagValues[i] = v;
            }

            int expectedXor = 0;
            foreach (int v in flagValues) expectedXor ^= v;

            FieldDef flagField = flagFields[0];

            int decoyCount = Math.Max(8, realCalls.Count / 2);
            var decoys = BuildDecoyMethods(module, moduleType, decoyCount);

            var newIns = new List<Instruction>();

            for (int i = 0; i < flagFields.Length; i++)
            {
                newIns.Add(OpCodes.Ldc_I4.ToInstruction(flagValues[i]));
                newIns.Add(OpCodes.Stsfld.ToInstruction(flagFields[i]));
            }

            foreach (var realCall in realCalls)
            {
                EmitJunk(newIns, decoys, 1 + rng.Next(3));

                int style = rng.Next(3);
                if (style == 0)
                    EmitOpaqueWrappedCallSimple(newIns, realCall, flagFields[rng.Next(flagFields.Length)]);
                else if (style == 1)
                    EmitOpaqueWrappedCallXor(newIns, realCall, flagFields, expectedXor);
                else
                    EmitOpaqueWrappedCallTwoField(newIns, realCall, flagFields, flagValues);
                EmitJunk(newIns, decoys, 1 + rng.Next(3));
            }

            foreach (var i in ins)
            {
                if (i.OpCode.Code == Code.Ret) continue;
                if (realCalls.Contains(i)) continue;

                if (i.OpCode.Code == Code.Nop) continue;
                newIns.Add(i);
            }
            newIns.Add(OpCodes.Ret.ToInstruction());

            ins.Clear();
            foreach (var i in newIns) ins.Add(i);
            cctor.Body.MaxStack = 8;
            cctor.Body.ExceptionHandlers.Clear();

            return realCalls.Count;
        }

        private void EmitOpaqueWrappedCallSimple(List<Instruction> sink, Instruction realCall,
                                                 FieldDef flagField)
        {
            var realLabel = realCall;
            var skipLabel = OpCodes.Nop.ToInstruction();
            sink.Add(OpCodes.Ldsfld.ToInstruction(flagField));
            sink.Add(OpCodes.Brtrue_S.ToInstruction(realLabel));
            sink.Add(OpCodes.Br_S.ToInstruction(skipLabel));
            sink.Add(realLabel);
            sink.Add(skipLabel);
        }

        private void EmitOpaqueWrappedCallXor(List<Instruction> sink, Instruction realCall,
                                              FieldDef[] flagFields, int expectedXor)
        {
            var realLabel = realCall;
            var skipLabel = OpCodes.Nop.ToInstruction();

            sink.Add(OpCodes.Ldsfld.ToInstruction(flagFields[0]));
            for (int i = 1; i < flagFields.Length; i++)
            {
                sink.Add(OpCodes.Ldsfld.ToInstruction(flagFields[i]));
                sink.Add(OpCodes.Xor.ToInstruction());
            }
            sink.Add(OpCodes.Ldc_I4.ToInstruction(expectedXor));
            sink.Add(OpCodes.Beq_S.ToInstruction(realLabel));
            sink.Add(OpCodes.Br_S.ToInstruction(skipLabel));
            sink.Add(realLabel);
            sink.Add(skipLabel);
        }

        private void EmitOpaqueWrappedCallTwoField(List<Instruction> sink,
                                                   Instruction realCall,
                                                   FieldDef[] flagFields,
                                                   int[] flagValues)
        {
            int a = rng.Next(flagFields.Length);
            int b = rng.Next(flagFields.Length);
            if (b == a) b = (b + 1) % flagFields.Length;
            int expected = unchecked(flagValues[a] + flagValues[b]);

            var realLabel = realCall;
            var skipLabel = OpCodes.Nop.ToInstruction();
            sink.Add(OpCodes.Ldsfld.ToInstruction(flagFields[a]));
            sink.Add(OpCodes.Ldsfld.ToInstruction(flagFields[b]));
            sink.Add(OpCodes.Add.ToInstruction());
            sink.Add(OpCodes.Ldc_I4.ToInstruction(expected));
            sink.Add(OpCodes.Beq_S.ToInstruction(realLabel));
            sink.Add(OpCodes.Br_S.ToInstruction(skipLabel));
            sink.Add(realLabel);
            sink.Add(skipLabel);
        }

        private void EmitJunk(List<Instruction> sink, List<MethodDef> decoys, int n)
        {
            if (decoys.Count == 0) { sink.Add(OpCodes.Nop.ToInstruction()); return; }
            for (int i = 0; i < n; i++)
            {
                int pick = rng.Next(4);
                switch (pick)
                {
                    case 0:

                        sink.Add(OpCodes.Call.ToInstruction(decoys[rng.Next(decoys.Count)]));
                        break;
                    case 1:

                        sink.Add(OpCodes.Ldc_I4.ToInstruction(rng.Next()));
                        sink.Add(OpCodes.Pop.ToInstruction());
                        break;
                    case 2:

                        sink.Add(OpCodes.Ldnull.ToInstruction());
                        sink.Add(OpCodes.Pop.ToInstruction());
                        break;
                    default:
                        sink.Add(OpCodes.Nop.ToInstruction());
                        break;
                }
            }
        }

        private FieldDef BuildOpaqueFlag(ModuleDef module, TypeDef moduleType)
        {
            var fld = new FieldDefUser(
                engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            moduleType.Fields.Add(fld);
            return fld;
        }

        private List<MethodDef> BuildDecoyMethods(ModuleDef module, TypeDef moduleType, int n)
        {

            var list = new List<MethodDef>();

            for (int i = 0; i < n; i++)
            {
                var sig = MethodSig.CreateStatic(module.CorLibTypes.Void);
                var m = new MethodDefUser(engine.MakeName(), sig,
                    dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig);
                m.Body = new CilBody();
                moduleType.Methods.Add(m);
                engine.injectedMethods.Add(m);
                list.Add(m);
            }

            for (int i = 0; i < n; i++)
            {
                MethodDef m = list[i];
                var ins = m.Body.Instructions;
                int shape = rng.Next(6);

                bool heavy = rng.Next(10) < 4;
                int iters = heavy ? (20000 + rng.Next(60000)) : (3 + rng.Next(15));
                switch (shape)
                {
                    case 0:
                        for (int k = 0; k < iters; k++)
                        {
                            ins.Add(OpCodes.Ldc_I4.ToInstruction(rng.Next()));
                            ins.Add(OpCodes.Pop.ToInstruction());
                        }
                        break;
                    case 1:
                        for (int k = 0; k < iters; k++)
                        {
                            ins.Add(OpCodes.Ldnull.ToInstruction());
                            ins.Add(OpCodes.Pop.ToInstruction());
                        }
                        break;
                    case 2:
                        ins.Add(OpCodes.Ldc_I4.ToInstruction(rng.Next()));
                        for (int k = 0; k < iters; k++)
                        {
                            ins.Add(OpCodes.Ldc_I4.ToInstruction(rng.Next()));
                            int op = rng.Next(4);
                            if (op == 0) ins.Add(OpCodes.Add.ToInstruction());
                            else if (op == 1) ins.Add(OpCodes.Xor.ToInstruction());
                            else if (op == 2) ins.Add(OpCodes.Or.ToInstruction());
                            else ins.Add(OpCodes.And.ToInstruction());
                        }
                        ins.Add(OpCodes.Pop.ToInstruction());
                        break;
                    case 3:

                        if (i >= n - 1)
                        {

                            for (int k = 0; k < iters; k++)
                            {
                                ins.Add(OpCodes.Ldc_I4.ToInstruction(rng.Next()));
                                ins.Add(OpCodes.Pop.ToInstruction());
                            }
                        }
                        else
                        {
                            for (int k = 0; k < iters; k++)
                            {
                                int j = i + 1 + rng.Next(n - i - 1);
                                ins.Add(OpCodes.Call.ToInstruction(list[j]));
                            }
                        }
                        break;
                    case 4:
                        for (int k = 0; k < iters; k++)
                        {
                            int p = rng.Next(3);
                            if (p == 0) ins.Add(OpCodes.Nop.ToInstruction());
                            else if (p == 1) { ins.Add(OpCodes.Ldstr.ToInstruction("")); ins.Add(OpCodes.Pop.ToInstruction()); }
                            else { ins.Add(OpCodes.Ldc_I4_0.ToInstruction()); ins.Add(OpCodes.Pop.ToInstruction()); }
                        }
                        break;
                    default:
                        var endL = OpCodes.Ret.ToInstruction();
                        ins.Add(OpCodes.Ldc_I4_1.ToInstruction());
                        ins.Add(OpCodes.Brfalse_S.ToInstruction(endL));
                        for (int k = 0; k < iters; k++)
                        {
                            ins.Add(OpCodes.Ldc_I4.ToInstruction(rng.Next()));
                            ins.Add(OpCodes.Pop.ToInstruction());
                        }
                        ins.Add(endL);
                        break;
                }
                if (ins.Count == 0 || ins[ins.Count - 1].OpCode.Code != Code.Ret)
                    ins.Add(OpCodes.Ret.ToInstruction());
                m.Body.MaxStack = 8;
            }
            return list;
        }
    }
}

