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
    internal class MethodInlinerProtection
    {
        private const int MAX_BODY = 48;
        private const int MAX_TOTAL_INLINES = 240;

        private Obfuscation engine;
        private Random rng;

        internal MethodInlinerProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyMethodInliner(ModuleDef module)
        {
            var callSites = BuildCallSiteMap(module);
            int budget = MAX_TOTAL_INLINES;
            var consumed = new HashSet<MethodDef>();

            foreach (var entry in callSites)
            {
                if (budget <= 0) break;
                if (entry.Value.Count != 1) continue;

                MethodDef callee = entry.Key;
                if (consumed.Contains(callee)) continue;
                if (!IsInlineable(callee)) continue;

                var siteInfo = entry.Value[0];
                MethodDef caller = siteInfo.Caller;
                Instruction callInst = siteInfo.Inst;

                if (caller == callee) continue;
                if (!CanReceiveInlining(caller, callee, callInst)) continue;

                bool ok;
                try { ok = SpliceInline(caller, callee, callInst); }
                catch { ok = false; }

                if (ok)
                {
                    consumed.Add(callee);
                    budget--;
                }
            }
        }

        private struct CallSite
        {
            public MethodDef Caller;
            public Instruction Inst;
        }

        private Dictionary<MethodDef, List<CallSite>> BuildCallSiteMap(ModuleDef module)
        {
            var map = new Dictionary<MethodDef, List<CallSite>>();
            var ftnRefs = new HashSet<MethodDef>();

            foreach (TypeDef type in module.GetTypes())
            {
                foreach (MethodDef caller in type.Methods)
                {
                    if (!caller.HasBody) continue;
                    foreach (Instruction ins in caller.Body.Instructions)
                    {
                        if (ins.OpCode == DnOpCodes.Ldftn || ins.OpCode == DnOpCodes.Ldvirtftn)
                        {
                            var t = ins.Operand as MethodDef;
                            if (t != null) ftnRefs.Add(t);
                        }
                        if (ins.OpCode != DnOpCodes.Call) continue;
                        var callee = ins.Operand as MethodDef;
                        if (callee == null) continue;
                        if (callee.Module != module) continue;

                        List<CallSite> bucket;
                        if (!map.TryGetValue(callee, out bucket))
                        {
                            bucket = new List<CallSite>();
                            map[callee] = bucket;
                        }
                        bucket.Add(new CallSite { Caller = caller, Inst = ins });
                    }
                }
            }

            var pruned = new Dictionary<MethodDef, List<CallSite>>();
            foreach (var kv in map)
            {
                if (ftnRefs.Contains(kv.Key)) continue;
                pruned[kv.Key] = kv.Value;
            }
            return pruned;
        }

        private bool IsInlineable(MethodDef callee)
        {
            if (callee == null || !callee.HasBody) return false;
            if (!callee.IsStatic) return false;
            if (callee.IsConstructor || callee.IsStaticConstructor) return false;
            if (callee.HasGenericParameters) return false;
            if (callee.DeclaringType == null) return false;
            if (callee.DeclaringType.HasGenericParameters) return false;
            if (callee.IsVirtual || callee.IsAbstract) return false;
            if (callee.IsPinvokeImpl) return false;
            if (callee.Body.HasExceptionHandlers) return false;
            if (callee.Body.Instructions.Count > MAX_BODY) return false;
            if (engine.IsCompilerGenerated(callee.DeclaringType)) return false;
            if (engine.injectedMethods.Contains(callee)) return false;
            if (engine.IsWinFormsType(callee.DeclaringType)) return false;
            if (engine.MethodHasAsyncOrIteratorAttribute(callee)) return false;

            if (engine.IsMethodUserExcluded(callee)) return false;
            if (callee.MethodSig == null) return false;

            var ps = callee.MethodSig.Params;
            if (ps != null)
            {
                foreach (var p in ps)
                {
                    if (p.IsByRef) return false;
                    if (p.IsPointer) return false;
                    if (p.FullName == "System.TypedReference") return false;
                }
            }
            if (callee.Body.Variables != null)
            {
                foreach (var v in callee.Body.Variables)
                {
                    if (v.Type != null && v.Type.IsPointer) return false;
                }
            }

            int retCount = 0;
            int lastIdx = callee.Body.Instructions.Count - 1;
            for (int i = 0; i <= lastIdx; i++)
            {
                var ins = callee.Body.Instructions[i];
                var c = ins.OpCode.Code;
                if (c == Code.Ldarga || c == Code.Ldarga_S) return false;
                if (c == Code.Starg || c == Code.Starg_S) return false;
                if (c == Code.Ret)
                {
                    retCount++;
                    if (i != lastIdx) return false;
                }
                if (c == Code.Jmp) return false;
                if (c == Code.Localloc) return false;
                if (c == Code.Endfilter || c == Code.Endfinally) return false;
                if (c == Code.Tailcall) return false;
                if (c == Code.Arglist) return false;
            }
            if (retCount != 1) return false;

            return true;
        }

        private bool CanReceiveInlining(MethodDef caller, MethodDef callee, Instruction callInst)
        {
            if (caller == null || !caller.HasBody) return false;
            if (engine.injectedMethods.Contains(caller)) return false;
            if (caller.HasGenericParameters) return false;
            if (caller.DeclaringType != null && caller.DeclaringType.HasGenericParameters) return false;
            if (engine.IsCompilerGenerated(caller.DeclaringType)) return false;
            if (engine.IsWinFormsType(caller.DeclaringType)) return false;
            if (engine.MethodHasAsyncOrIteratorAttribute(caller)) return false;

            if (engine.IsMethodUserExcluded(caller)) return false;

            if (caller.Body.HasExceptionHandlers)
            {
                foreach (var eh in caller.Body.ExceptionHandlers)
                {
                    if (Spans(eh.TryStart, eh.TryEnd, callInst, caller)) return false;
                    if (Spans(eh.HandlerStart, eh.HandlerEnd, callInst, caller)) return false;
                }
            }

            if (caller.DeclaringType != callee.DeclaringType)
            {
                if (CrossesAccessBoundary(callee, caller)) return false;
            }
            return true;
        }

        private bool CrossesAccessBoundary(MethodDef callee, MethodDef caller)
        {
            var body = callee.Body;
            if (body == null) return false;
            ModuleDef calleeMod = callee.Module;
            TypeDef callerType = caller.DeclaringType;

            foreach (var ins in body.Instructions)
            {
                object op = ins.Operand;
                if (op == null) continue;

                TypeDef td = null;
                MethodDef md = null;
                FieldDef fd = null;

                var asType = op as ITypeDefOrRef;
                if (asType != null) td = asType.ResolveTypeDef();

                var asMethod = op as IMethod;
                if (asMethod != null && !(asMethod is MethodSpec))
                {
                    try { md = asMethod.ResolveMethodDef(); } catch { md = null; }
                    if (md == null && asMethod.DeclaringType != null)
                        td = td ?? asMethod.DeclaringType.ResolveTypeDef();
                }

                var asField = op as IField;
                if (asField != null)
                {
                    try { fd = asField.ResolveFieldDef(); } catch { fd = null; }
                    if (fd == null && asField.DeclaringType != null)
                        td = td ?? asField.DeclaringType.ResolveTypeDef();
                }

                if (md != null && md.Module == calleeMod)
                {
                    if (!IsMethodVisibleFrom(md, callerType)) return true;
                }
                if (fd != null && fd.Module == calleeMod)
                {
                    if (!IsFieldVisibleFrom(fd, callerType)) return true;
                }
                if (td != null && td.Module == calleeMod)
                {
                    if (!IsTypeVisibleFrom(td, callerType)) return true;
                }
            }
            return false;
        }

        private bool IsTypeVisibleFrom(TypeDef target, TypeDef from)
        {
            TypeDef cur = target;
            while (cur != null)
            {
                if (!cur.IsNested) return true;
                var vis = cur.Visibility;
                TypeDef enc = cur.DeclaringType;
                if (vis == DnTypeAttributes.NestedPublic ||
                    vis == DnTypeAttributes.NestedAssembly ||
                    vis == DnTypeAttributes.NestedFamORAssem)
                {
                    cur = enc;
                    continue;
                }
                if (vis == DnTypeAttributes.NestedFamily ||
                    vis == DnTypeAttributes.NestedFamANDAssem)
                {
                    if (!IsSameOrDerivedFrom(from, enc)) return false;
                    cur = enc;
                    continue;
                }
                if (!IsSameOrNestedInside(from, enc)) return false;
                cur = enc;
            }
            return true;
        }

        private bool IsMethodVisibleFrom(MethodDef m, TypeDef from)
        {
            if (m.DeclaringType != null && !IsTypeVisibleFrom(m.DeclaringType, from)) return false;
            var a = m.Access;
            if (a == DnMethodAttributes.Public ||
                a == DnMethodAttributes.Assembly ||
                a == DnMethodAttributes.FamORAssem) return true;
            if (a == DnMethodAttributes.Family ||
                a == DnMethodAttributes.FamANDAssem)
                return IsSameOrDerivedFrom(from, m.DeclaringType);
            return IsSameOrNestedInside(from, m.DeclaringType);
        }

        private bool IsFieldVisibleFrom(FieldDef f, TypeDef from)
        {
            if (f.DeclaringType != null && !IsTypeVisibleFrom(f.DeclaringType, from)) return false;
            var a = f.Access;
            if (a == DnFieldAttributes.Public ||
                a == DnFieldAttributes.Assembly ||
                a == DnFieldAttributes.FamORAssem) return true;
            if (a == DnFieldAttributes.Family ||
                a == DnFieldAttributes.FamANDAssem)
                return IsSameOrDerivedFrom(from, f.DeclaringType);
            return IsSameOrNestedInside(from, f.DeclaringType);
        }

        private bool IsSameOrNestedInside(TypeDef inner, TypeDef outer)
        {
            if (outer == null || inner == null) return false;
            TypeDef cur = inner;
            while (cur != null)
            {
                if (cur == outer) return true;
                cur = cur.DeclaringType;
            }
            return false;
        }

        private bool IsSameOrDerivedFrom(TypeDef sub, TypeDef baseT)
        {
            if (sub == null || baseT == null) return false;
            TypeDef cur = sub;
            int guard = 0;
            while (cur != null && guard++ < 32)
            {
                if (cur == baseT) return true;
                if (cur.BaseType == null) break;
                cur = cur.BaseType.ResolveTypeDef();
            }
            return false;
        }

        private bool Spans(Instruction start, Instruction end, Instruction probe, MethodDef caller)
        {
            if (start == null || end == null) return false;
            int sIdx = caller.Body.Instructions.IndexOf(start);
            int eIdx = caller.Body.Instructions.IndexOf(end);
            int pIdx = caller.Body.Instructions.IndexOf(probe);
            return sIdx <= pIdx && pIdx < eIdx;
        }

        private bool SpliceInline(MethodDef caller, MethodDef callee, Instruction callInst)
        {
            var calBody = caller.Body;
            int callIdx = calBody.Instructions.IndexOf(callInst);
            if (callIdx < 0) return false;

            int paramCount = callee.Parameters.Count;
            var paramSlots = new Local[paramCount];
            for (int i = 0; i < paramCount; i++)
            {
                paramSlots[i] = new Local(callee.Parameters[i].Type);
                calBody.Variables.Add(paramSlots[i]);
            }

            var localMap = new Dictionary<Local, Local>();
            if (callee.Body.Variables != null)
            {
                foreach (var lv in callee.Body.Variables)
                {
                    var nl = new Local(lv.Type);
                    calBody.Variables.Add(nl);
                    localMap[lv] = nl;
                }
            }

            var afterCall = (callIdx + 1 < calBody.Instructions.Count)
                ? calBody.Instructions[callIdx + 1]
                : null;
            if (afterCall == null)
            {
                afterCall = Instruction.Create(DnOpCodes.Nop);
                calBody.Instructions.Add(afterCall);
            }

            callInst.OpCode = DnOpCodes.Nop;
            callInst.Operand = null;

            int writeAt = callIdx + 1;
            for (int p = paramCount - 1; p >= 0; p--)
            {
                calBody.Instructions.Insert(writeAt, Instruction.Create(DnOpCodes.Stloc, paramSlots[p]));
                writeAt++;
            }

            var srcBody = callee.Body;
            int srcCount = srcBody.Instructions.Count;
            var clones = new Instruction[srcCount];
            var instMap = new Dictionary<Instruction, Instruction>(srcCount);

            for (int i = 0; i < srcCount; i++)
            {
                var src = srcBody.Instructions[i];
                Instruction dst;

                if (src.OpCode == DnOpCodes.Ret)
                {
                    dst = Instruction.Create(DnOpCodes.Br, afterCall);
                }
                else if (src.IsLdarg())
                {
                    int pi = src.GetParameterIndex();
                    if (pi < 0 || pi >= paramCount) return false;
                    dst = Instruction.Create(DnOpCodes.Ldloc, paramSlots[pi]);
                }
                else if (src.IsStarg())
                {
                    int pi = src.GetParameterIndex();
                    if (pi < 0 || pi >= paramCount) return false;
                    dst = Instruction.Create(DnOpCodes.Stloc, paramSlots[pi]);
                }
                else if (src.IsLdloc())
                {
                    var lv = src.GetLocal(srcBody.Variables);
                    Local mapped;
                    if (lv == null || !localMap.TryGetValue(lv, out mapped)) return false;
                    dst = Instruction.Create(DnOpCodes.Ldloc, mapped);
                }
                else if (src.IsStloc())
                {
                    var lv = src.GetLocal(srcBody.Variables);
                    Local mapped;
                    if (lv == null || !localMap.TryGetValue(lv, out mapped)) return false;
                    dst = Instruction.Create(DnOpCodes.Stloc, mapped);
                }
                else
                {
                    dst = new Instruction(src.OpCode, src.Operand);
                }

                clones[i] = dst;
                instMap[src] = dst;
            }

            for (int i = 0; i < srcCount; i++)
            {
                var dst = clones[i];
                var asInst = dst.Operand as Instruction;
                if (asInst != null && instMap.ContainsKey(asInst))
                {
                    dst.Operand = instMap[asInst];
                    continue;
                }
                var asArr = dst.Operand as Instruction[];
                if (asArr != null)
                {
                    var copy = new Instruction[asArr.Length];
                    for (int k = 0; k < asArr.Length; k++)
                    {
                        if (asArr[k] != null && instMap.ContainsKey(asArr[k]))
                            copy[k] = instMap[asArr[k]];
                        else
                            copy[k] = asArr[k];
                    }
                    dst.Operand = copy;
                }
            }

            for (int i = 0; i < srcCount; i++)
            {
                calBody.Instructions.Insert(writeAt, clones[i]);
                writeAt++;
            }

            calBody.InitLocals = true;
            return true;
        }
    }
}

