using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class DesignerSplitProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int TARGET_CHUNKS = 12;

        private const int MIN_INSTRUCTIONS_TO_SPLIT = 120;

        private const int MIN_CHUNK_INSTRUCTIONS = 12;

        internal DesignerSplitProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        private static void Log(string msg)
        {

        }

        internal int ApplyDesignerSplit(ModuleDef module)
        {
            Log("[start]");
            int totalChunks = 0;
            int typesScanned = 0, formsSeen = 0;
            foreach (TypeDef t in module.GetTypes())
            {
                typesScanned++;
                if (engine.injectedTypes.Contains(t)) continue;
                if (!engine.IsWinFormsType(t)) continue;

                if (engine.IsTypeUserExcluded(t)) continue;
                formsSeen++;
                Log("Form type: " + t.FullName);

                MethodDef ic = null;
                foreach (var m in t.Methods)
                {
                    if (m == null || !m.HasBody) continue;
                    if (m.Name != "InitializeComponent") continue;
                    ic = m;
                    break;
                }
                if (ic == null) { Log("  no IC found on " + t.FullName); continue; }

                if (engine.IsMethodUserExcluded(ic)) { Log("  IC method user-excluded, skip"); continue; }
                int len = ic.Body.Instructions.Count;
                Log("  IC found, instructions=" + len + ", locals=" + ic.Body.Variables.Count);
                if (len < MIN_INSTRUCTIONS_TO_SPLIT) { Log("  too short, skip"); continue; }

                try
                {
                    int chunks = SplitIC(t, ic);
                    Log("  SplitIC returned " + chunks + " chunks");
                    totalChunks += chunks;
                }
                catch (Exception ex)
                {
                    Log("  EXCEPTION: " + ex.GetType().Name + " " + ex.Message);
                }
            }
            Log("[done] typesScanned=" + typesScanned + " formsSeen=" + formsSeen + " totalChunks=" + totalChunks);
            return totalChunks;
        }

        private int SplitIC(TypeDef formType, MethodDef ic)
        {
            Log("  SplitIC: SimplifyMacros...");
            ic.Body.SimplifyMacros(ic.Parameters);
            ic.Body.SimplifyBranches();

            Log("  SplitIC: ConvertLocalsToFields (locals=" + ic.Body.Variables.Count + ", instr=" + ic.Body.Instructions.Count + ")...");
            ConvertLocalsToFields(formType, ic);

            Log("  SplitIC: ComputeSafeSplitPoints (after-convert instr=" + ic.Body.Instructions.Count + ")...");
            var insns = ic.Body.Instructions;
            int n = insns.Count;
            bool[] safe = ComputeSafeSplitPoints(ic);
            if (safe == null) { Log("  ComputeSafeSplitPoints returned null"); return 0; }

            Log("  SplitIC: ChooseEvenlySpread...");
            List<int> cuts = ChooseEvenlySpread(safe, n);
            Log("  cuts=" + cuts.Count);
            if (cuts.Count == 0) return 0;

            List<int[]> chunks = new List<int[]>();
            int prev = 0;
            foreach (int c in cuts)
            {
                chunks.Add(new int[] { prev, c });
                prev = c;
            }
            chunks.Add(new int[] { prev, n });

            List<MethodDef> subMethods = new List<MethodDef>();
            foreach (var range in chunks)
            {
                int start = range[0], end = range[1];
                if (end - start < MIN_CHUNK_INSTRUCTIONS) continue;
                MethodDef sub = MakeSubMethod(formType, ic, start, end);
                if (sub != null) subMethods.Add(sub);
            }
            if (subMethods.Count < 2) return 0;

            RewriteICBody(ic, subMethods);

            return subMethods.Count;
        }

        private void ConvertLocalsToFields(TypeDef formType, MethodDef ic)
        {
            var body = ic.Body;
            if (body.Variables.Count == 0) return;

            int origCount = body.Variables.Count;
            var localFields = new FieldDef[origCount];
            for (int i = 0; i < origCount; i++)
            {
                Local L = body.Variables[i];
                FieldDef F = new FieldDefUser(
                    engine.MakeName(),
                    new FieldSig(L.Type),
                    DnFieldAttributes.Private);
                formType.Fields.Add(F);
                localFields[i] = F;
            }

            var ins = body.Instructions;
            int srcCount = ins.Count;

            var newIns = new List<Instruction>(srcCount * 2);

            var tempFieldByTypeName = new Dictionary<string, FieldDef>();

            for (int i = 0; i < srcCount; i++)
            {
                Instruction instr = ins[i];
                Local local = instr.Operand as Local;
                int idx = (local != null) ? body.Variables.IndexOf(local) : -1;

                if (local == null || idx < 0 || idx >= origCount)
                {

                    newIns.Add(instr);
                    continue;
                }

                FieldDef F = localFields[idx];
                Code c = instr.OpCode.Code;

                if (c == Code.Ldloc || c == Code.Ldloc_S)
                {

                    instr.OpCode = DnOpCodes.Ldarg_0;
                    instr.Operand = null;
                    newIns.Add(instr);
                    newIns.Add(OpCodes.Ldfld.ToInstruction(F));
                }
                else if (c == Code.Stloc || c == Code.Stloc_S)
                {

                    string key = local.Type != null ? local.Type.FullName : "?";
                    if (!tempFieldByTypeName.TryGetValue(key, out FieldDef tempF))
                    {
                        tempF = new FieldDefUser(
                            engine.MakeName(),
                            new FieldSig(local.Type),
                            DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                        formType.Fields.Add(tempF);
                        tempFieldByTypeName[key] = tempF;
                    }
                    instr.OpCode = DnOpCodes.Stsfld;
                    instr.Operand = tempF;
                    newIns.Add(instr);
                    newIns.Add(OpCodes.Ldarg_0.ToInstruction());
                    newIns.Add(OpCodes.Ldsfld.ToInstruction(tempF));
                    newIns.Add(OpCodes.Stfld.ToInstruction(F));
                }
                else if (c == Code.Ldloca || c == Code.Ldloca_S)
                {

                    instr.OpCode = DnOpCodes.Ldarg_0;
                    instr.Operand = null;
                    newIns.Add(instr);
                    newIns.Add(OpCodes.Ldflda.ToInstruction(F));
                }
                else
                {

                    newIns.Add(instr);
                }
            }

            ins.Clear();
            foreach (var x in newIns) ins.Add(x);
        }

        private bool[] ComputeSafeSplitPoints(MethodDef ic)
        {
            var ins = ic.Body.Instructions;
            int n = ins.Count;
            if (n == 0) return null;

            int[] depth = new int[n + 1];
            depth[0] = 0;
            for (int i = 0; i < n; i++)
            {
                int delta = StackDelta(ins[i]);
                depth[i + 1] = depth[i] + delta;
                if (depth[i + 1] < 0)
                {

                    return null;
                }
            }

            var idxOf = new Dictionary<Instruction, int>(n);
            for (int i = 0; i < n; i++) idxOf[ins[i]] = i;

            bool[] blocked = new bool[n + 1];

            for (int i = 0; i < n; i++)
            {
                Instruction br = ins[i];
                int oc = (int)br.OpCode.OperandType;

                if (br.Operand is Instruction tgt)
                {
                    if (idxOf.TryGetValue(tgt, out int tgtIdx))
                    {
                        int lo = Math.Min(i, tgtIdx);
                        int hi = Math.Max(i, tgtIdx);
                        for (int k = lo + 1; k <= hi; k++) blocked[k] = true;
                    }
                }
                else if (br.Operand is Instruction[] targets)
                {
                    foreach (var t in targets)
                    {
                        if (t != null && idxOf.TryGetValue(t, out int tgtIdx))
                        {
                            int lo = Math.Min(i, tgtIdx);
                            int hi = Math.Max(i, tgtIdx);
                            for (int k = lo + 1; k <= hi; k++) blocked[k] = true;
                        }
                    }
                }
            }

            if (ic.Body.HasExceptionHandlers)
            {
                foreach (var eh in ic.Body.ExceptionHandlers)
                {
                    BlockRange(idxOf, blocked, eh.TryStart, eh.TryEnd);
                    BlockRange(idxOf, blocked, eh.HandlerStart, eh.HandlerEnd);
                    BlockRange(idxOf, blocked, eh.FilterStart, eh.HandlerStart);
                }
            }

            bool[] safe = new bool[n + 1];
            for (int k = 1; k < n; k++)
            {
                if (depth[k] == 0 && !blocked[k]) safe[k] = true;
            }

            for (int k = Math.Max(0, n - 3); k <= n; k++) safe[k] = false;

            return safe;
        }

        private void BlockRange(Dictionary<Instruction, int> idxOf, bool[] blocked,
            Instruction start, Instruction end)
        {
            if (start == null) return;
            if (!idxOf.TryGetValue(start, out int s)) return;
            int e;
            if (end == null) e = blocked.Length - 1;
            else if (!idxOf.TryGetValue(end, out e)) return;
            for (int k = s; k <= e && k < blocked.Length; k++) blocked[k] = true;
        }

        private static int StackDelta(Instruction ins)
        {

            int pushes, pops;
            ins.CalculateStackUsage(out pushes, out pops);
            return pushes - pops;
        }

        private List<int> ChooseEvenlySpread(bool[] safe, int n)
        {

            var cuts = new List<int>();
            int targetGap = Math.Max(MIN_CHUNK_INSTRUCTIONS, n / TARGET_CHUNKS);
            int lastCut = 0;
            for (int k = 1; k < n; k++)
            {
                if (!safe[k]) continue;
                if (k - lastCut < targetGap) continue;
                cuts.Add(k);
                lastCut = k;
                if (cuts.Count >= TARGET_CHUNKS) break;
            }
            return cuts;
        }

        private MethodDef MakeSubMethod(TypeDef formType, MethodDef ic, int start, int end)
        {

            ModuleDef mod = formType.Module;
            MethodSig sig = MethodSig.CreateInstance(mod.CorLibTypes.Void);
            MethodDef sub = new MethodDefUser(
                engine.MakeName(),
                sig,
                DnMethodAttributes.Private | DnMethodAttributes.HideBySig);
            sub.Body = new CilBody();
            sub.Body.InitLocals = true;

            var srcIns = ic.Body.Instructions;
            var dstIns = sub.Body.Instructions;

            var localMap = new Dictionary<Local, Local>();
            var clone = new Dictionary<Instruction, Instruction>();

            for (int k = start; k < end; k++)
            {
                Instruction src = srcIns[k];
                object op = src.Operand;
                if (op is Local L)
                {
                    if (!localMap.TryGetValue(L, out Local newL))
                    {
                        newL = new Local(L.Type);
                        sub.Body.Variables.Add(newL);
                        localMap[L] = newL;
                    }
                    op = newL;
                }
                Instruction dst = new Instruction(src.OpCode, op);
                dst.SequencePoint = null;
                clone[src] = dst;
                dstIns.Add(dst);
            }

            foreach (Instruction dst in dstIns)
            {
                if (dst.Operand is Instruction tgt)
                {
                    if (clone.TryGetValue(tgt, out var nt)) dst.Operand = nt;

                }
                else if (dst.Operand is Instruction[] targets)
                {
                    var newTargets = new Instruction[targets.Length];
                    for (int t = 0; t < targets.Length; t++)
                    {
                        if (targets[t] != null && clone.TryGetValue(targets[t], out var nt))
                            newTargets[t] = nt;
                        else
                            newTargets[t] = targets[t];
                    }
                    dst.Operand = newTargets;
                }
            }

            while (dstIns.Count > 0)
            {
                var last = dstIns[dstIns.Count - 1];
                if (last.OpCode.Code == Code.Ret) { dstIns.RemoveAt(dstIns.Count - 1); continue; }
                break;
            }
            dstIns.Add(OpCodes.Ret.ToInstruction());

            sub.Body.MaxStack = 8;

            if (ic.Body.HasExceptionHandlers)
            {
                int hStart = start, hEnd = end;
                int IndexOfOrMinusOne(Instruction probe)
                {
                    if (probe == null) return -1;
                    for (int k = 0; k < srcIns.Count; k++)
                        if (srcIns[k] == probe) return k;
                    return -1;
                }
                foreach (var eh in ic.Body.ExceptionHandlers)
                {
                    int ts = IndexOfOrMinusOne(eh.TryStart);
                    int te = IndexOfOrMinusOne(eh.TryEnd);
                    int hs = IndexOfOrMinusOne(eh.HandlerStart);
                    int he = IndexOfOrMinusOne(eh.HandlerEnd);
                    if (ts < 0 || he < 0) continue;

                    int minIdx = ts;
                    int maxIdx = he;
                    if (te >= 0) maxIdx = Math.Max(maxIdx, te);
                    if (hs >= 0) maxIdx = Math.Max(maxIdx, hs);
                    if (minIdx < hStart || maxIdx > hEnd) continue;

                    Instruction ToCloned(Instruction src2)
                    {
                        if (src2 == null) return null;
                        return clone.TryGetValue(src2, out var c2) ? c2 : null;
                    }
                    var newEh = new ExceptionHandler(eh.HandlerType)
                    {
                        TryStart     = ToCloned(eh.TryStart),
                        TryEnd       = ToCloned(eh.TryEnd),
                        HandlerStart = ToCloned(eh.HandlerStart),
                        HandlerEnd   = ToCloned(eh.HandlerEnd),
                        FilterStart  = ToCloned(eh.FilterStart),
                        CatchType    = eh.CatchType,
                    };
                    if (newEh.TryStart != null && newEh.HandlerStart != null)
                        sub.Body.ExceptionHandlers.Add(newEh);
                }
            }

            formType.Methods.Add(sub);
            engine.designerSplitSubMethods.Add(sub);
            return sub;
        }

        private void RewriteICBody(MethodDef ic, List<MethodDef> subMethods)
        {

            var body = ic.Body;
            body.Instructions.Clear();
            body.ExceptionHandlers.Clear();

            foreach (var sub in subMethods)
            {
                body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                body.Instructions.Add(OpCodes.Call.ToInstruction(sub));
            }
            body.Instructions.Add(OpCodes.Ret.ToInstruction());
            body.MaxStack = 1;
        }
    }
}

