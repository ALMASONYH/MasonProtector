using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class ControlFlowProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal ControlFlowProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyControlFlow(ModuleDef module)
        {

            bool allowDesigner = engine.cfg != null && engine.cfg.MaximumEncryption;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method, allowDesigner)) continue;
                    if (method.IsConstructor || method.IsStaticConstructor) continue;
                    if (method.Body.HasExceptionHandlers) continue;
                    if (method.Body.Instructions.Count < 4) continue;
                    if (HasAnyBranch(method.Body.Instructions)) continue;
                    if (method == module.EntryPoint) continue;
                    try
                    {
                        FlattenControlFlow(module, method);
                        engine.controlFlowFlattenedMethods.Add(method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }
        }

        private class DispatchEntry
        {
            public int Hash;
            public Instruction Target;
            public bool IsReal;
            public int RealIdx;
        }

        private void FlattenControlFlow(ModuleDef module, MethodDef method)
        {
            method.Body.SimplifyBranches();
            method.Body.SimplifyMacros(method.Parameters);

            var il = method.Body.Instructions;
            if (il.Count < 4) return;

            var blocks = SplitIntoBlocks(il);
            if (blocks.Count < 2) return;
            if (blocks.Count > 160) return;

            var stateA = new Local(module.CorLibTypes.Int32);
            var stateB = new Local(module.CorLibTypes.Int32);
            var stateC = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(stateA);
            method.Body.Variables.Add(stateB);
            method.Body.Variables.Add(stateC);

            int[] hashes = new int[blocks.Count];
            var used = new HashSet<int>();
            for (int i = 0; i < blocks.Count; i++)
            {
                int h;
                do { h = rng.Next(1024, int.MaxValue); }
                while (used.Contains(h));
                hashes[i] = h;
                used.Add(h);
            }

            int bogusCount = Math.Min(blocks.Count / 2 + 2, 20);
            int[] bogusHashes = new int[bogusCount];
            for (int i = 0; i < bogusCount; i++)
            {
                int h;
                do { h = rng.Next(1024, int.MaxValue); }
                while (used.Contains(h));
                bogusHashes[i] = h;
                used.Add(h);
            }

            int initB = rng.Next();
            int initC = rng.Next();
            int initA = hashes[0] ^ initB ^ initC;

            var blockEntries = new Instruction[blocks.Count];
            for (int i = 0; i < blocks.Count; i++)
                blockEntries[i] = Instruction.Create(DnOpCodes.Nop);

            var bogusEntries = new Instruction[bogusCount];
            for (int i = 0; i < bogusCount; i++)
                bogusEntries[i] = Instruction.Create(DnOpCodes.Nop);

            var loopHead = Instruction.Create(DnOpCodes.Nop);
            var exitPoint = Instruction.Create(DnOpCodes.Ret);

            var newIl = new List<Instruction>();

            newIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, initA));
            newIl.Add(Instruction.Create(DnOpCodes.Stloc, stateA));
            newIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, initB));
            newIl.Add(Instruction.Create(DnOpCodes.Stloc, stateB));
            newIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, initC));
            newIl.Add(Instruction.Create(DnOpCodes.Stloc, stateC));

            newIl.Add(loopHead);

            var allEntries = new List<DispatchEntry>();
            for (int i = 0; i < blocks.Count; i++)
                allEntries.Add(new DispatchEntry { Hash = hashes[i], Target = blockEntries[i], IsReal = true, RealIdx = i });
            for (int i = 0; i < bogusCount; i++)
                allEntries.Add(new DispatchEntry { Hash = bogusHashes[i], Target = bogusEntries[i], IsReal = false, RealIdx = -1 });
            allEntries = allEntries.OrderBy(_ => rng.Next()).ToList();

            foreach (var entry in allEntries)
            {
                EmitStateKey(newIl, stateA, stateB, stateC);
                newIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, entry.Hash));
                newIl.Add(Instruction.Create(DnOpCodes.Beq, entry.Target));
            }

            newIl.Add(Instruction.Create(DnOpCodes.Br, exitPoint));

            int[] deltaA = new int[blocks.Count];
            int[] deltaB = new int[blocks.Count];
            int[] deltaC = new int[blocks.Count];
            for (int i = 0; i < blocks.Count - 1; i++)
            {
                deltaA[i] = rng.Next();
                deltaB[i] = rng.Next();
                deltaC[i] = deltaA[i] ^ deltaB[i] ^ hashes[i] ^ hashes[i + 1];
            }

            int[] shuffled = Enumerable.Range(0, blocks.Count).OrderBy(_ => rng.Next()).ToArray();
            foreach (int blockIdx in shuffled)
            {
                var block = blocks[blockIdx];

                newIl.Add(blockEntries[blockIdx]);

                foreach (var inst in block)
                {
                    if (inst.OpCode == DnOpCodes.Ret)
                        newIl.Add(Instruction.Create(DnOpCodes.Br, exitPoint));
                    else
                        newIl.Add(inst);
                }

                if (blockIdx < blocks.Count - 1)
                {

                    newIl.Add(Instruction.Create(DnOpCodes.Ldloc, stateA));
                    newIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, deltaA[blockIdx]));
                    newIl.Add(Instruction.Create(DnOpCodes.Xor));
                    newIl.Add(Instruction.Create(DnOpCodes.Stloc, stateA));

                    newIl.Add(Instruction.Create(DnOpCodes.Ldloc, stateB));
                    newIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, deltaB[blockIdx]));
                    newIl.Add(Instruction.Create(DnOpCodes.Xor));
                    newIl.Add(Instruction.Create(DnOpCodes.Stloc, stateB));

                    newIl.Add(Instruction.Create(DnOpCodes.Ldloc, stateC));
                    newIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, deltaC[blockIdx]));
                    newIl.Add(Instruction.Create(DnOpCodes.Xor));
                    newIl.Add(Instruction.Create(DnOpCodes.Stloc, stateC));

                    newIl.Add(Instruction.Create(DnOpCodes.Br, loopHead));
                }
                else
                {
                    newIl.Add(Instruction.Create(DnOpCodes.Br, exitPoint));
                }
            }

            for (int i = 0; i < bogusCount; i++)
            {
                newIl.Add(bogusEntries[i]);
                EmitBogusBlock(newIl, stateA, stateB, stateC);
                newIl.Add(Instruction.Create(DnOpCodes.Br, exitPoint));
            }

            newIl.Add(exitPoint);

            il.Clear();
            foreach (var inst in newIl)
                il.Add(inst);

            method.Body.OptimizeBranches();
        }

        private void EmitStateKey(List<Instruction> il, Local sA, Local sB, Local sC)
        {
            int variant = rng.Next(0, 3);
            switch (variant)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sA));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sB));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sC));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sB));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sC));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sA));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sC));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sA));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc, sB));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
            }
        }

        private void EmitBogusBlock(List<Instruction> il, Local sA, Local sB, Local sC)
        {
            int ops = rng.Next(3, 7);
            for (int i = 0; i < ops; i++)
            {
                Local target;
                int pick = rng.Next(0, 3);
                if (pick == 0) target = sA;
                else if (pick == 1) target = sB;
                else target = sC;

                int op = rng.Next(0, 5);
                switch (op)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc, target));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc, target));
                        break;
                    case 1:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc, target));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        il.Add(Instruction.Create(DnOpCodes.Stloc, target));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc, target));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc, target));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc, target));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Stloc, target));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc, target));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        il.Add(Instruction.Create(DnOpCodes.Stloc, target));
                        break;
                }
            }
        }

        private List<List<Instruction>> SplitIntoBlocks(IList<Instruction> il)
        {
            int[] depths = new int[il.Count + 1];
            int d = 0;
            for (int i = 0; i < il.Count; i++)
            {
                depths[i] = d;
                d += GetStackDelta(il[i]);
                if (d < 0) d = 0;
            }
            depths[il.Count] = d;

            var blocks = new List<List<Instruction>>();
            var current = new List<Instruction>();
            int blockSize = rng.Next(2, 4);
            int count = 0;

            for (int i = 0; i < il.Count; i++)
            {
                current.Add(il[i]);
                count++;

                bool isTerminator = il[i].OpCode == DnOpCodes.Ret ||
                    il[i].OpCode == DnOpCodes.Br || il[i].OpCode == DnOpCodes.Br_S ||
                    il[i].OpCode == DnOpCodes.Throw || il[i].OpCode == DnOpCodes.Rethrow;

                bool atStackZero = depths[i + 1] == 0;

                if ((count >= blockSize && atStackZero) || isTerminator || i == il.Count - 1)
                {
                    blocks.Add(current);
                    current = new List<Instruction>();
                    count = 0;
                    blockSize = rng.Next(2, 4);
                }
            }

            if (current.Count > 0) blocks.Add(current);
            return blocks;
        }

        private int GetStackDelta(Instruction inst)
        {
            int push = 0, pop = 0;
            switch (inst.OpCode.StackBehaviourPush)
            {
                case StackBehaviour.Push0: push = 0; break;
                case StackBehaviour.Push1:
                case StackBehaviour.Pushi:
                case StackBehaviour.Pushi8:
                case StackBehaviour.Pushr4:
                case StackBehaviour.Pushr8:
                case StackBehaviour.Pushref: push = 1; break;
                case StackBehaviour.Push1_push1: push = 2; break;
                case StackBehaviour.Varpush:
                    if (inst.OpCode == DnOpCodes.Call || inst.OpCode == DnOpCodes.Callvirt || inst.OpCode == DnOpCodes.Newobj)
                    {
                        var mr = inst.Operand as IMethod;
                        if (mr != null && mr.MethodSig != null && mr.MethodSig.RetType != null &&
                            mr.MethodSig.RetType.FullName != "System.Void")
                            push = 1;
                    }
                    break;
                default: push = 0; break;
            }
            switch (inst.OpCode.StackBehaviourPop)
            {
                case StackBehaviour.Pop0: pop = 0; break;
                case StackBehaviour.Pop1:
                case StackBehaviour.Popi:
                case StackBehaviour.Popref: pop = 1; break;
                case StackBehaviour.Pop1_pop1:
                case StackBehaviour.Popi_pop1:
                case StackBehaviour.Popi_popi:
                case StackBehaviour.Popi_popi8:
                case StackBehaviour.Popi_popr4:
                case StackBehaviour.Popi_popr8:
                case StackBehaviour.Popref_pop1:
                case StackBehaviour.Popref_popi: pop = 2; break;
                case StackBehaviour.Popi_popi_popi:
                case StackBehaviour.Popref_popi_popi:
                case StackBehaviour.Popref_popi_popi8:
                case StackBehaviour.Popref_popi_popr4:
                case StackBehaviour.Popref_popi_popr8:
                case StackBehaviour.Popref_popi_popref:
                case StackBehaviour.Popref_popi_pop1: pop = 3; break;
                case StackBehaviour.Varpop:
                    if (inst.OpCode == DnOpCodes.Call || inst.OpCode == DnOpCodes.Callvirt || inst.OpCode == DnOpCodes.Newobj)
                    {
                        var m = inst.Operand as IMethod;
                        if (m != null && m.MethodSig != null)
                        {
                            pop = m.MethodSig.Params.Count;
                            if (m.MethodSig.HasThis && inst.OpCode != DnOpCodes.Newobj) pop++;
                        }
                    }
                    break;
                default: pop = 0; break;
            }
            return push - pop;
        }

        private bool HasAnyBranch(IList<Instruction> il)
        {
            for (int i = 0; i < il.Count; i++)
            {
                var fc = il[i].OpCode.FlowControl;
                if (fc == FlowControl.Cond_Branch) return true;
                if (fc == FlowControl.Branch) return true;
                if (il[i].OpCode == DnOpCodes.Switch) return true;
            }
            return false;
        }
    }
}

