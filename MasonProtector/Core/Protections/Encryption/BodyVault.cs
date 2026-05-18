using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class BodyVaultProtection
    {
        private Obfuscation engine;
        private Random rng;

        private List<IMethod> importMethods;
        private List<ITypeDefOrRef> importMethodDeclTypes;
        private Dictionary<uint, int> importMethodMap;
        private List<IField> importFields;
        private List<ITypeDefOrRef> importFieldDeclTypes;
        private Dictionary<uint, int> importFieldMap;
        private List<ITypeDefOrRef> importTypes;
        private Dictionary<uint, int> importTypeMap;
        private List<string> importStrings;
        private Dictionary<string, int> importStringMap;

        internal BodyVaultProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyBodyVault(ModuleDef userModule, TypeDef modType)
        {
            var candidates = new List<MethodDef>();
            foreach (TypeDef t in userModule.GetTypes())
            {

                if (engine.IsCompilerGenerated(t)) continue;
                if (engine.injectedTypes.Contains(t)) continue;
                if (engine.IsVBInfrastructure(t)) continue;
                if (t.HasGenericParameters) continue;

                if (engine.IsTypeUserExcluded(t)) continue;
                foreach (MethodDef m in t.Methods)
                {
                    if (engine.IsMethodUserExcluded(m)) continue;
                    if (IsCandidate(m)) candidates.Add(m);
                }
            }
            if (candidates.Count == 0) return;

            string protectorPath = typeof(BodyVaultProtection).Assembly.Location;
            ModuleDefMD srcModule = ModuleDefMD.Load(protectorPath);
            TypeDef srcHelper = srcModule.Find(
                "MasonProtector.Core.RuntimeStubs.BodyVaultRuntime", false);
            if (srcHelper == null) return;

            var cloner = new TypeCloner(srcModule, userModule);
            string helperName = engine.MakeName();
            TypeDef dstHelper = cloner.CloneType(srcHelper, "", helperName);
            engine.injectedTypes.Add(dstHelper);
            foreach (var dm in dstHelper.Methods) engine.injectedMethods.Add(dm);

            FieldDef fName = dstHelper.FindField("_resName");
            FieldDef fLock = dstHelper.FindField("_lock");
            FieldDef fMh     = dstHelper.FindField("_mh");
            FieldDef fDh     = dstHelper.FindField("_dh");
            FieldDef fFh     = dstHelper.FindField("_fh");
            FieldDef fFdh    = dstHelper.FindField("_fdh");
            FieldDef fTh     = dstHelper.FindField("_th");
            FieldDef fUs     = dstHelper.FindField("_us");
            FieldDef fPepper = dstHelper.FindField("_pepper");
            FieldDef fIters  = dstHelper.FindField("_iters");
            MethodDef mRun = dstHelper.FindMethod("Run");
            if (fName == null || mRun == null ||
                fMh == null || fDh == null || fFh == null || fFdh == null ||
                fTh == null || fUs == null ||
                fPepper == null || fIters == null)
                return;

            foreach (MethodDef hm in dstHelper.Methods)
            {
                if (hm.IsConstructor || hm.IsStaticConstructor) continue;
                hm.Name = engine.MakeName();
            }
            foreach (FieldDef hf in dstHelper.Fields)
            {
                hf.Name = engine.MakeName();
            }

            byte[] aesKey = engine.CryptoRandom(32);
            byte[] aesIv  = engine.CryptoRandom(16);

            byte[] xorSeedBuf = engine.CryptoRandom(1);
            byte xorSeed = (byte)(1 + (xorSeedBuf[0] % 254));

            byte[] salt   = engine.CryptoRandom(16);
            byte[] pepperReal = engine.CryptoRandom(128);

            int iters     = 300000 + rng.Next(200001);
            byte[] padding = engine.CryptoRandom((salt[0] & 0x3F) + 1);

            byte[] pepper = new byte[pepperReal.Length];
            {
                string envName = "";
                if (userModule.Assembly != null)
                {
                    var nm = userModule.Assembly.Name;
                    if ((object)nm != null) envName = nm.String ?? "";
                }
                byte[] envSeed = System.Text.Encoding.UTF8.GetBytes("bvenv:" + envName);
                byte[] envMask;
                using (var sh = System.Security.Cryptography.SHA256.Create())
                    envMask = sh.ComputeHash(envSeed);
                for (int i = 0; i < pepper.Length; i++)
                    pepper[i] = (byte)(pepperReal[i] ^ envMask[i % envMask.Length]);
                System.Array.Clear(envMask, 0, envMask.Length);
            }

            string resName = "$" + engine.MakeName().Replace(".", "_");

            importMethods         = new List<IMethod>();
            importMethodDeclTypes = new List<ITypeDefOrRef>();
            importMethodMap       = new Dictionary<uint, int>();
            importFields          = new List<IField>();
            importFieldDeclTypes  = new List<ITypeDefOrRef>();
            importFieldMap        = new Dictionary<uint, int>();
            importTypes           = new List<ITypeDefOrRef>();
            importTypeMap         = new Dictionary<uint, int>();
            importStrings         = new List<string>();
            importStringMap       = new Dictionary<string, int>(StringComparer.Ordinal);
            var captured = new List<Captured>();
            foreach (MethodDef m in candidates)
            {
                Captured c;
                try
                {
                    c = CaptureBody(m, userModule);
                }
                catch
                {
                    continue;
                }
                if (c == null) continue;
                captured.Add(c);
            }
            if (captured.Count == 0) return;
            for (int i = 0; i < captured.Count; i++)
                captured[i].Index = i;

            byte[] plainBlob = AssembleBlob(captured);

            byte[] sealedBlob = SealBlob(plainBlob, aesKey, aesIv, xorSeed);

            byte[] mask = DeriveMask(pepperReal, salt, iters, 81);
            byte[] scrambledIv  = new byte[16];
            byte[] scrambledKey = new byte[32];
            for (int i = 0; i < 16; i++) scrambledIv[i]  = (byte)(aesIv[i]  ^ mask[i]);
            for (int i = 0; i < 32; i++) scrambledKey[i] = (byte)(aesKey[i] ^ mask[16 + i]);
            byte wrappedXor = (byte)(xorSeed ^ mask[48]);
            byte[] hmacKey = new byte[32];
            Buffer.BlockCopy(mask, 49, hmacKey, 0, 32);

            byte[] hmac;
            using (var h = new HMACSHA256(hmacKey))
                hmac = h.ComputeHash(sealedBlob);

            int pl = 16 + 16 + 32 + 1 + padding.Length + 32 + sealedBlob.Length;
            byte[] resourcePayload = new byte[pl];
            int wp = 0;
            Buffer.BlockCopy(salt,         0, resourcePayload, wp, 16);                 wp += 16;
            Buffer.BlockCopy(scrambledIv,  0, resourcePayload, wp, 16);                 wp += 16;
            Buffer.BlockCopy(scrambledKey, 0, resourcePayload, wp, 32);                 wp += 32;
            resourcePayload[wp++] = wrappedXor;
            Buffer.BlockCopy(padding,      0, resourcePayload, wp, padding.Length);     wp += padding.Length;
            Buffer.BlockCopy(hmac,         0, resourcePayload, wp, 32);                 wp += 32;
            Buffer.BlockCopy(sealedBlob,   0, resourcePayload, wp, sealedBlob.Length);

            Array.Clear(aesKey, 0, aesKey.Length);
            Array.Clear(aesIv,  0, aesIv.Length);
            Array.Clear(mask,   0, mask.Length);
            Array.Clear(hmacKey, 0, hmacKey.Length);
            Array.Clear(hmac,   0, hmac.Length);

            userModule.Resources.Add(new EmbeddedResource(resName, resourcePayload,
                ManifestResourceAttributes.Private));
            engine.injectedResources.Add(resName);

            ReplaceCctor(userModule, dstHelper, fName, fLock,
                fMh, fDh, fFh, fFdh, fTh, fUs,
                fPepper, fIters, pepper, iters,
                resName);

            Array.Clear(pepper,     0, pepper.Length);
            Array.Clear(pepperReal, 0, pepperReal.Length);

            MethodDef obfMarkerCtor = BuildObfuscatedByFreemasonryAttribute(userModule);

            foreach (Captured c in captured)
            {
                BuildStub(c.Method, c.Index, mRun, userModule);

                engine.bodyVaultedStubs.Add(c.Method);

                if (obfMarkerCtor != null && (engine.rng.Next(2) == 0))
                {
                    try
                    {
                        c.Method.CustomAttributes.Add(new CustomAttribute(obfMarkerCtor));
                    }
                    catch { }
                }
            }

            if (obfMarkerCtor != null)
            {
                try { StampMarkerDecoys(userModule, obfMarkerCtor, captured); } catch { }
            }
        }

        private void StampMarkerDecoys(ModuleDef userModule, MethodDef obfMarkerCtor,
                                       List<Captured> captured)
        {

            var vaultedSet = new HashSet<MethodDef>();
            foreach (var c in captured) vaultedSet.Add(c.Method);

            var pool = new List<MethodDef>();
            foreach (TypeDef t in userModule.GetTypes())
            {

                if (t == obfMarkerCtor.DeclaringType) continue;

                if (engine.IsTypeUserExcluded(t)) continue;
                foreach (MethodDef m in t.Methods)
                {
                    if (m == null || !m.HasBody) continue;
                    if (vaultedSet.Contains(m)) continue;

                    if (m.IsConstructor || m.IsStaticConstructor) continue;

                    if (m.Body.Instructions.Count < 4) continue;
                    if (engine.IsMethodUserExcluded(m)) continue;
                    pool.Add(m);
                }
            }
            if (pool.Count == 0) return;

            int decoyCount = Math.Max(captured.Count * 8, pool.Count / 8);
            if (decoyCount > pool.Count) decoyCount = pool.Count;

            for (int i = pool.Count - 1; i > 0; i--)
            {
                int j = engine.rng.Next(i + 1);
                var tmp = pool[i]; pool[i] = pool[j]; pool[j] = tmp;
            }

            for (int i = 0; i < decoyCount; i++)
            {
                try
                {
                    var ca = new CustomAttribute(obfMarkerCtor);
                    pool[i].CustomAttributes.Add(ca);
                }
                catch { }
            }
        }

        private MethodDef BuildObfuscatedByFreemasonryAttribute(ModuleDef userModule)
        {
            try
            {
                var attrBase = userModule.Import(typeof(System.Attribute));
                var attrType = new TypeDefUser("", engine.MakeName(), attrBase);
                attrType.Attributes = dnlib.DotNet.TypeAttributes.NotPublic |
                    dnlib.DotNet.TypeAttributes.Sealed |
                    dnlib.DotNet.TypeAttributes.BeforeFieldInit;
                userModule.Types.Add(attrType);
                engine.injectedTypes.Add(attrType);

                var attrBaseCtor = userModule.Import(typeof(System.Attribute).GetConstructor(
                    BindingFlags.NonPublic | BindingFlags.Instance,
                    null, Type.EmptyTypes, null));

                var ctor = new MethodDefUser(".ctor",
                    MethodSig.CreateInstance(userModule.CorLibTypes.Void),
                    dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed,
                    dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.HideBySig |
                    dnlib.DotNet.MethodAttributes.SpecialName | dnlib.DotNet.MethodAttributes.RTSpecialName);
                ctor.Body = new CilBody();
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, attrBaseCtor));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                attrType.Methods.Add(ctor);
                engine.injectedMethods.Add(ctor);

                try
                {
                    var usageType = userModule.Import(typeof(System.AttributeUsageAttribute));
                    var usageCtor = (ICustomAttributeType)userModule.Import(typeof(System.AttributeUsageAttribute)
                        .GetConstructor(new[] { typeof(System.AttributeTargets) }));
                    var usageCa = new CustomAttribute(usageCtor,
                        new CAArgument[]
                        {
                            new CAArgument(userModule.Import(typeof(System.AttributeTargets)).ToTypeSig(),
                                (int)System.AttributeTargets.All)
                        });
                    attrType.CustomAttributes.Add(usageCa);
                }
                catch { }

                return ctor;
            }
            catch { return null; }
        }

        private bool IsCandidate(MethodDef m)
        {
            if (!m.HasBody || !m.Body.HasInstructions) return false;
            if (engine.injectedMethods.Contains(m)) return false;

            if (m.IsConstructor && !m.IsStaticConstructor) return false;

            if (m.IsStaticConstructor && m.DeclaringType != null && m.DeclaringType.Name == "<Module>")
                return false;

            if (m.IsStaticConstructor && m.DeclaringType != null &&
                (m.DeclaringType.HasGenericParameters || engine.injectedTypes.Contains(m.DeclaringType)))
                return false;

            if (m.IsAbstract) return false;
            if (m.IsPinvokeImpl) return false;
            if (m.HasGenericParameters) return false;
            if (!m.IsStatic && (m.DeclaringType == null || m.DeclaringType.IsValueType))
                return false;

            if (m.Name == "Main") return false;
            if (m.Name == ".ctor") return false;

            if (m.IsRuntimeSpecialName && !m.IsStaticConstructor) return false;
            if (m.Name.StartsWith("<")) return false;
            if (m.Name.StartsWith("VB$")) return false;
            if (m.HasOverrides) return false;

            if (m.Name == "InitializeComponent") return false;
            if (m.Name == "Dispose" && m.MethodSig != null &&
                m.MethodSig.Params.Count == 1 &&
                m.MethodSig.Params[0].FullName == "System.Boolean" &&
                m.DeclaringType != null && engine.IsWinFormsType(m.DeclaringType))
                return false;

            if (engine.designerSplitSubMethods.Contains(m)) return false;

            foreach (var ca in m.CustomAttributes)
            {
                if (ca.AttributeType == null) continue;
                string fn = ca.AttributeType.FullName;
                if (fn == "System.Runtime.CompilerServices.AsyncStateMachineAttribute") return false;
                if (fn == "System.Runtime.CompilerServices.IteratorStateMachineAttribute") return false;
                if (fn == "System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute") return false;
            }

            if (m.DeclaringType != null)
            {
                if (m.DeclaringType.HasGenericParameters) return false;
            }

            MethodSig sig = m.MethodSig;
            if (sig == null) return false;
            if (!IsSimpleType(sig.RetType)) return false;

            foreach (var p in sig.Params)
                if (!IsSimpleTypeOrByRef(p)) return false;

            int methodSpecCount = 0;
            foreach (Instruction ins in m.Body.Instructions)
            {
                Code c = ins.OpCode.Code;
                if (c == Code.Calli || c == Code.Localloc || c == Code.Jmp)
                    return false;

                if (ins.Operand is MethodSpec)
                {
                    methodSpecCount++;
                    MethodSpec ms = (MethodSpec)ins.Operand;
                    if (ms.GenericInstMethodSig != null)
                    {
                        foreach (TypeSig gArg in ms.GenericInstMethodSig.GenericArguments)
                        {
                            if (gArg == null) return false;
                            if (gArg is GenericSig) return false;
                            if (HasOpenGenericInside(gArg)) return false;
                        }
                    }
                }

                if (ins.OpCode.OperandType == OperandType.InlineSig) return false;

                ITypeDefOrRef tref = ins.Operand as ITypeDefOrRef;
                if (tref != null && HasOpenGenericInside(tref.ToTypeSig())) return false;
            }
            if (methodSpecCount > 32) return false;

            if (m.Body.Instructions.Count > 20000) return false;

            return true;
        }

        private static bool HasOpenGenericInside(TypeSig ts)
        {
            if (ts == null) return false;
            ts = ts.RemovePinnedAndModifiers();
            if (ts == null) return false;
            if (ts is GenericSig) return true;
            GenericInstSig gi = ts as GenericInstSig;
            if (gi != null)
            {
                foreach (TypeSig a in gi.GenericArguments)
                    if (HasOpenGenericInside(a)) return true;
                return HasOpenGenericInside(gi.GenericType);
            }
            if (ts.Next != null) return HasOpenGenericInside(ts.Next);
            return false;
        }

        private bool IsSimpleType(TypeSig ts)
        {
            if (ts == null) return false;
            ts = ts.RemovePinnedAndModifiers();
            if (ts == null) return false;
            if (ts is ByRefSig)   return false;
            if (ts is PtrSig)     return false;
            if (ts is GenericSig) return false;
            if (ts is FnPtrSig)   return false;
            return true;
        }

        private bool IsSimpleTypeOrByRef(TypeSig ts)
        {
            if (ts == null) return false;
            ts = ts.RemovePinnedAndModifiers();
            if (ts == null) return false;
            if (ts is PtrSig)     return false;
            if (ts is GenericSig) return false;
            if (ts is FnPtrSig)   return false;
            ByRefSig brs = ts as ByRefSig;
            if (brs != null)
                return IsSimpleType(brs.Next);
            return true;
        }

        private class Captured
        {
            public MethodDef Method;
            public uint Token;
            public int Index;
            public byte[] Code;
            public byte[] LocalSig;
            public int MaxStack;
            public int[] TokenSiteOffsets;
            public CapturedEh[] Eh;
        }

        private class CapturedEh
        {
            public uint Flags;
            public int  TryStart;
            public int  TryLength;
            public int  HandlerStart;
            public int  HandlerLength;
            public int  FilterStart;
            public int  CatchTypeSentinel;
        }

        private Captured CaptureBody(MethodDef m, ModuleDef module)
        {
            CilBody body = m.Body;
            body.SimplifyBranches();
            body.OptimizeBranches();

            var instrs = body.Instructions;
            int[] offsets = new int[instrs.Count];
            int p = 0;
            for (int i = 0; i < instrs.Count; i++)
            {
                offsets[i] = p;
                p += instrs[i].GetSize();
            }
            int byteLen = p;

            byte[] code = new byte[byteLen];
            var tokenSites = new List<int>();

            for (int i = 0; i < instrs.Count; i++)
            {
                Instruction ins = instrs[i];
                int o = offsets[i];
                ushort code16 = (ushort)ins.OpCode.Value;
                if (code16 < 0x100)
                {
                    code[o] = (byte)code16;
                    o++;
                }
                else
                {
                    code[o]     = (byte)(code16 >> 8);
                    code[o + 1] = (byte)(code16 & 0xFF);
                    o += 2;
                }

                OperandType ot = ins.OpCode.OperandType;
                switch (ot)
                {
                    case OperandType.InlineNone:
                        break;
                    case OperandType.ShortInlineI:
                    case OperandType.ShortInlineVar:
                    case OperandType.ShortInlineBrTarget:
                        EncodeShortOperand(ins, code, o, instrs, offsets, i);
                        break;
                    case OperandType.InlineI:
                    case OperandType.InlineBrTarget:
                        EncodeInt32Operand(ins, code, o, instrs, offsets, i);
                        break;
                    case OperandType.InlineI8:
                        WriteInt64(code, o, (long)ins.Operand);
                        break;
                    case OperandType.ShortInlineR:
                        WriteFloat32(code, o, (float)ins.Operand);
                        break;
                    case OperandType.InlineR:
                        WriteFloat64(code, o, (double)ins.Operand);
                        break;
                    case OperandType.InlineVar:
                        EncodeInlineVar(ins, code, o);
                        break;
                    case OperandType.InlineString:
                    case OperandType.InlineMethod:
                    case OperandType.InlineField:
                    case OperandType.InlineType:
                    case OperandType.InlineSig:
                    case OperandType.InlineTok:
                    {
                        int sentinel = RegisterImport(ins.OpCode.OperandType,
                            ins.Operand);
                        WriteInt32(code, o, sentinel);
                        tokenSites.Add(o);
                        break;
                    }
                    case OperandType.InlineSwitch:
                    {
                        Instruction[] tgts = (Instruction[])ins.Operand;
                        WriteInt32(code, o, tgts.Length);
                        int baseAfter = o + 4 + tgts.Length * 4;
                        for (int j = 0; j < tgts.Length; j++)
                        {
                            int diff = OffsetOf(tgts[j], instrs, offsets) - baseAfter;
                            WriteInt32(code, o + 4 + j * 4, diff);
                        }
                        break;
                    }
                    default:
                        return null;
                }
            }

            byte[] localSig;
            if (body.HasVariables && body.Variables.Count > 0)
            {
                localSig = BuildLocalSig(module, body);
                if (localSig == null) return null;
            }
            else
            {
                localSig = new byte[] { 0x07, 0x00 };
            }

            uint computed;
            if (!dnlib.DotNet.Writer.MaxStackCalculator.GetMaxStack(
                    body.Instructions, body.ExceptionHandlers, out computed))
            {
                computed = (uint)body.MaxStack;
            }
            int maxStackToStore = (int)computed;
            if (maxStackToStore < body.MaxStack) maxStackToStore = body.MaxStack;
            if (maxStackToStore < 8) maxStackToStore = 8;

            CapturedEh[] ehArr;
            if (body.HasExceptionHandlers && body.ExceptionHandlers.Count > 0)
            {
                var ehList = new List<CapturedEh>(body.ExceptionHandlers.Count);
                foreach (ExceptionHandler eh in body.ExceptionHandlers)
                {
                    uint flags;
                    switch (eh.HandlerType)
                    {
                        case ExceptionHandlerType.Catch:   flags = 0x0; break;
                        case ExceptionHandlerType.Filter:  flags = 0x1; break;
                        case ExceptionHandlerType.Finally: flags = 0x2; break;
                        case ExceptionHandlerType.Fault:   flags = 0x4; break;
                        default: return null;
                    }

                    int tryStart  = OffsetOf(eh.TryStart,    instrs, offsets);
                    int tryEnd    = eh.TryEnd != null
                                      ? OffsetOf(eh.TryEnd,  instrs, offsets)
                                      : byteLen;
                    int hStart    = OffsetOf(eh.HandlerStart,instrs, offsets);
                    int hEnd      = eh.HandlerEnd != null
                                      ? OffsetOf(eh.HandlerEnd, instrs, offsets)
                                      : byteLen;
                    int fStart    = (flags == 0x1 && eh.FilterStart != null)
                                      ? OffsetOf(eh.FilterStart, instrs, offsets)
                                      : 0;

                    int catchSent = 0;
                    if (flags == 0x0)
                    {
                        if (eh.CatchType == null) return null;
                        catchSent = MakeSentinel(2, RegisterType(eh.CatchType));
                    }

                    ehList.Add(new CapturedEh
                    {
                        Flags             = flags,
                        TryStart          = tryStart,
                        TryLength         = tryEnd - tryStart,
                        HandlerStart      = hStart,
                        HandlerLength     = hEnd - hStart,
                        FilterStart       = fStart,
                        CatchTypeSentinel = catchSent,
                    });
                }
                ehArr = ehList.ToArray();
            }
            else
            {
                ehArr = new CapturedEh[0];
            }

            var c = new Captured
            {
                Method = m,
                Token = m.MDToken.Raw,
                Code = code,
                LocalSig = localSig,
                MaxStack = maxStackToStore,
                TokenSiteOffsets = tokenSites.ToArray(),
                Eh = ehArr,
            };
            return c;
        }

        private void EncodeShortOperand(Instruction ins, byte[] code, int o,
            IList<Instruction> instrs, int[] offsets, int curIdx)
        {
            OperandType ot = ins.OpCode.OperandType;
            if (ot == OperandType.ShortInlineBrTarget)
            {
                int diff = OffsetOf((Instruction)ins.Operand, instrs, offsets) - (o + 1);
                code[o] = (byte)(sbyte)diff;
            }
            else if (ot == OperandType.ShortInlineI)
            {
                object op = ins.Operand;
                if      (op is sbyte) code[o] = (byte)(sbyte)op;
                else if (op is byte)  code[o] = (byte)op;
                else if (op is int)   code[o] = (byte)(int)op;
                else                  code[o] = 0;
            }
            else
            {
                EncodeShortVar(ins, code, o);
            }
        }

        private void EncodeShortVar(Instruction ins, byte[] code, int o)
        {
            object op = ins.Operand;
            Local lv = op as Local;
            Parameter pv = op as Parameter;
            if      (lv != null) code[o] = (byte)lv.Index;
            else if (pv != null) code[o] = (byte)pv.Index;
            else                 code[o] = (byte)Convert.ToInt32(op);
        }

        private void EncodeInlineVar(Instruction ins, byte[] code, int o)
        {
            object op = ins.Operand;
            Local lv = op as Local;
            Parameter pv = op as Parameter;
            ushort idx;
            if      (lv != null) idx = (ushort)lv.Index;
            else if (pv != null) idx = (ushort)pv.Index;
            else                 idx = (ushort)Convert.ToInt32(op);
            code[o]     = (byte)(idx & 0xFF);
            code[o + 1] = (byte)((idx >> 8) & 0xFF);
        }

        private void EncodeInt32Operand(Instruction ins, byte[] code, int o,
            IList<Instruction> instrs, int[] offsets, int curIdx)
        {
            OperandType ot = ins.OpCode.OperandType;
            if (ot == OperandType.InlineBrTarget)
            {
                int diff = OffsetOf((Instruction)ins.Operand, instrs, offsets) - (o + 4);
                WriteInt32(code, o, diff);
            }
            else
            {
                object op = ins.Operand;
                int v;
                if      (op is int)  v = (int)op;
                else if (op is uint) v = (int)(uint)op;
                else                 v = Convert.ToInt32(op);
                WriteInt32(code, o, v);
            }
        }

        private int OffsetOf(Instruction target, IList<Instruction> all, int[] offsets)
        {
            for (int i = 0; i < all.Count; i++)
                if (all[i] == target) return offsets[i];
            return 0;
        }

        private static int MakeSentinel(int kind, int idx)
        {
            return unchecked((int)(0x80000000u
                | ((uint)kind << 24)
                | ((uint)idx & 0xFFFFFFu)));
        }

        private int RegisterImport(OperandType ot, object operand)
        {
            if (operand is string)
            {
                string s = (string)operand;
                int idx;
                if (!importStringMap.TryGetValue(s, out idx))
                {
                    idx = importStrings.Count;
                    importStrings.Add(s);
                    importStringMap[s] = idx;
                }
                return MakeSentinel(3, idx);
            }

            if (ot == OperandType.InlineSig)
                throw new NotSupportedException("InlineSig (calli) not supported");

            MemberRef mr = operand as MemberRef;
            if (mr != null)
            {
                if (mr.IsMethodRef)
                    return MakeSentinel(0, RegisterMethod(mr));
                if (mr.IsFieldRef)
                    return MakeSentinel(1, RegisterField(mr));
                throw new NotSupportedException("MemberRef neither method nor field");
            }

            if (operand is MethodSpec)
                return MakeSentinel(0, RegisterMethod((IMethod)operand));
            if (operand is MethodDef)
                return MakeSentinel(0, RegisterMethod((IMethod)operand));

            if (operand is FieldDef)
                return MakeSentinel(1, RegisterField((IField)operand));

            ITypeDefOrRef td = operand as ITypeDefOrRef;
            if (td != null)
                return MakeSentinel(2, RegisterType(td));

            throw new NotSupportedException(
                "unsupported token operand: " + operand.GetType().FullName);
        }

        private int RegisterMethod(IMethod m)
        {
            uint tok = m.MDToken.Raw;
            int idx;
            if (!importMethodMap.TryGetValue(tok, out idx))
            {
                idx = importMethods.Count;
                importMethods.Add(m);
                importMethodDeclTypes.Add(GetMethodDeclType(m));
                importMethodMap[tok] = idx;
            }
            return idx;
        }

        private int RegisterField(IField f)
        {
            uint tok = f.MDToken.Raw;
            int idx;
            if (!importFieldMap.TryGetValue(tok, out idx))
            {
                idx = importFields.Count;
                importFields.Add(f);
                importFieldDeclTypes.Add(GetFieldDeclType(f));
                importFieldMap[tok] = idx;
            }
            return idx;
        }

        private static ITypeDefOrRef GetMethodDeclType(IMethod m)
        {
            MemberRef mr = m as MemberRef;
            if (mr != null) return mr.DeclaringType;
            MethodSpec ms = m as MethodSpec;
            if (ms != null && ms.Method != null)
            {
                return GetMethodDeclType(ms.Method);
            }
            MethodDef md = m as MethodDef;
            if (md != null) return md.DeclaringType;
            return m.DeclaringType;
        }

        private static ITypeDefOrRef GetFieldDeclType(IField f)
        {
            MemberRef mr = f as MemberRef;
            if (mr != null) return mr.DeclaringType;
            FieldDef fd = f as FieldDef;
            if (fd != null) return fd.DeclaringType;
            return f.DeclaringType;
        }

        private int RegisterType(ITypeDefOrRef t)
        {
            uint tok = t.MDToken.Raw;
            int idx;
            if (!importTypeMap.TryGetValue(tok, out idx))
            {
                idx = importTypes.Count;
                importTypes.Add(t);
                importTypeMap[tok] = idx;
            }
            return idx;
        }

        private byte[] BuildLocalSig(ModuleDef module, CilBody body)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0x07);
                WriteCompressedUInt(ms, (uint)body.Variables.Count);
                foreach (Local l in body.Variables)
                {
                    if (!EncodeTypeSig(module, l.Type, ms))
                        return null;
                }
                return ms.ToArray();
            }
        }

        private static void WriteCompressedUInt(Stream s, uint v)
        {
            if (v <= 0x7F) { s.WriteByte((byte)v); return; }
            if (v <= 0x3FFF)
            {
                s.WriteByte((byte)((v >> 8) | 0x80));
                s.WriteByte((byte)(v & 0xFF));
                return;
            }
            s.WriteByte((byte)((v >> 24) | 0xC0));
            s.WriteByte((byte)((v >> 16) & 0xFF));
            s.WriteByte((byte)((v >> 8) & 0xFF));
            s.WriteByte((byte)(v & 0xFF));
        }

        private bool EncodeTypeSig(ModuleDef module, TypeSig ts, Stream s)
        {
            if (ts == null) { s.WriteByte((byte)ElementType.Object); return true; }
            bool pinned = false;
            for (TypeSig probe = ts; probe != null; probe = probe.Next)
            {
                if (probe is PinnedSig) { pinned = true; break; }
            }
            ts = ts.RemovePinnedAndModifiers();
            if (ts == null) { s.WriteByte((byte)ElementType.Object); return true; }
            if (pinned) s.WriteByte((byte)ElementType.Pinned);
            ElementType et = ts.ElementType;
            switch (et)
            {
                case ElementType.Void:
                case ElementType.Boolean:
                case ElementType.Char:
                case ElementType.I1: case ElementType.U1:
                case ElementType.I2: case ElementType.U2:
                case ElementType.I4: case ElementType.U4:
                case ElementType.I8: case ElementType.U8:
                case ElementType.R4: case ElementType.R8:
                case ElementType.String:
                case ElementType.Object:
                case ElementType.I:  case ElementType.U:
                case ElementType.TypedByRef:
                    s.WriteByte((byte)et);
                    return true;
                case ElementType.SZArray:
                    s.WriteByte((byte)ElementType.SZArray);
                    return EncodeTypeSig(module, ts.Next, s);
                case ElementType.Array:
                {
                    var arr = (ArraySig)ts;
                    s.WriteByte((byte)ElementType.Array);
                    if (!EncodeTypeSig(module, arr.Next, s)) return false;
                    WriteCompressedUInt(s, arr.Rank);
                    var sizes = arr.Sizes;
                    WriteCompressedUInt(s, (uint)(sizes != null ? sizes.Count : 0));
                    if (sizes != null)
                        foreach (uint sz in sizes) WriteCompressedUInt(s, sz);
                    var los = arr.LowerBounds;
                    WriteCompressedUInt(s, (uint)(los != null ? los.Count : 0));
                    if (los != null)
                        foreach (int lo in los) WriteCompressedInt(s, lo);
                    return true;
                }
                case ElementType.ByRef:
                    s.WriteByte((byte)ElementType.ByRef);
                    return EncodeTypeSig(module, ts.Next, s);
                case ElementType.Ptr:
                    s.WriteByte((byte)ElementType.Ptr);
                    return EncodeTypeSig(module, ts.Next, s);
                case ElementType.Class:
                case ElementType.ValueType:
                {
                    s.WriteByte((byte)et);
                    var tdr = ((ClassOrValueTypeSig)ts).TypeDefOrRef;
                    if (tdr == null) return false;
                    int sentinel = MakeSentinel(2, RegisterType(tdr));
                    WriteSentinel32(s, sentinel);
                    return true;
                }
                case ElementType.GenericInst:
                {
                    var gi = (GenericInstSig)ts;
                    var gtSig = gi.GenericType;
                    if (gtSig == null) return false;
                    var spec = ts.ToTypeDefOrRef();
                    if (spec == null) return false;
                    s.WriteByte((byte)gtSig.ElementType);
                    int sentinel = MakeSentinel(2, RegisterType(spec));
                    WriteSentinel32(s, sentinel);
                    return true;
                }
                case ElementType.Var:
                case ElementType.MVar:
                case ElementType.FnPtr:
                default:
                    return false;
            }
        }

        private static void WriteSentinel32(Stream s, int v)
        {
            s.WriteByte((byte)(v       & 0xFF));
            s.WriteByte((byte)((v >> 8) & 0xFF));
            s.WriteByte((byte)((v >> 16) & 0xFF));
            s.WriteByte((byte)((v >> 24) & 0xFF));
        }

        private static void WriteCompressedInt(Stream s, int v)
        {
            uint u;
            if (v >= 0) u = (uint)v << 1;
            else        u = (uint)(((-v) << 1) | 1);
            WriteCompressedUInt(s, u);
        }

        private byte[] AssembleBlob(List<Captured> entries)
        {
            int n = entries.Count;
            int headerLen = 4 + n * 4;
            int metaBlockLen = 9 * 4;
            int metaTotal = n * metaBlockLen;
            const int ehRecordLen = 7 * 4;

            int payload = 0;
            foreach (var c in entries)
            {
                payload += c.Code.Length;
                payload += c.LocalSig != null ? c.LocalSig.Length : 0;
                payload += c.TokenSiteOffsets.Length * 4;
                payload += (c.Eh != null ? c.Eh.Length : 0) * ehRecordLen;
            }
            int total = headerLen + metaTotal + payload;
            byte[] blob = new byte[total];
            int p = 0;

            WriteInt32(blob, p, n); p += 4;
            int metaBase = headerLen;
            for (int i = 0; i < n; i++)
            {
                WriteInt32(blob, p, metaBase + i * metaBlockLen); p += 4;
            }

            int metaP = headerLen;
            int payloadP = headerLen + metaTotal;
            foreach (var c in entries)
            {
                int codeOff = payloadP;
                Buffer.BlockCopy(c.Code, 0, blob, codeOff, c.Code.Length);
                payloadP += c.Code.Length;

                int locOff = c.LocalSig != null ? payloadP : 0;
                int locLen = c.LocalSig != null ? c.LocalSig.Length : 0;
                if (c.LocalSig != null)
                {
                    Buffer.BlockCopy(c.LocalSig, 0, blob, locOff, locLen);
                    payloadP += locLen;
                }

                int tokOff = payloadP;
                int tokCount = c.TokenSiteOffsets.Length;
                for (int j = 0; j < tokCount; j++)
                {
                    WriteInt32(blob, tokOff + j * 4, c.TokenSiteOffsets[j]);
                }
                payloadP += tokCount * 4;

                int ehOff   = payloadP;
                int ehCount = c.Eh != null ? c.Eh.Length : 0;
                if (ehCount > 0)
                {
                    for (int j = 0; j < ehCount; j++)
                    {
                        CapturedEh eh = c.Eh[j];
                        int b = ehOff + j * ehRecordLen;
                        WriteInt32(blob, b +  0, (int)eh.Flags);
                        WriteInt32(blob, b +  4, eh.TryStart);
                        WriteInt32(blob, b +  8, eh.TryLength);
                        WriteInt32(blob, b + 12, eh.HandlerStart);
                        WriteInt32(blob, b + 16, eh.HandlerLength);
                        WriteInt32(blob, b + 20, eh.FilterStart);
                        WriteInt32(blob, b + 24, eh.CatchTypeSentinel);
                    }
                    payloadP += ehCount * ehRecordLen;
                }

                WriteInt32(blob, metaP +  0, codeOff);
                WriteInt32(blob, metaP +  4, c.Code.Length);
                WriteInt32(blob, metaP +  8, locOff);
                WriteInt32(blob, metaP + 12, locLen);
                WriteInt32(blob, metaP + 16, c.MaxStack);
                WriteInt32(blob, metaP + 20, tokOff);
                WriteInt32(blob, metaP + 24, tokCount);
                WriteInt32(blob, metaP + 28, ehOff);
                WriteInt32(blob, metaP + 32, ehCount);
                metaP += metaBlockLen;
            }
            return blob;
        }

        private byte[] SealBlob(byte[] plain, byte[] key, byte[] iv, byte xorSeed)
        {
            byte[] compressed;
            using (var ms = new MemoryStream())
            {
                using (var ds = new DeflateStream(ms, CompressionMode.Compress, true))
                    ds.Write(plain, 0, plain.Length);
                compressed = ms.ToArray();
            }
            byte[] encrypted;
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var enc = aes.CreateEncryptor())
                    encrypted = enc.TransformFinalBlock(compressed, 0, compressed.Length);
            }
            for (int i = 0; i < encrypted.Length; i++)
                encrypted[i] ^= (byte)(xorSeed ^ (i & 0xFF));
            return encrypted;
        }

        private static byte[] DeriveMask(byte[] pepper, byte[] salt, int iters, int length)
        {
            byte[] password;
            using (HMACSHA256 hm = new HMACSHA256(pepper))
                password = hm.ComputeHash(salt);
            byte[] mask;
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, iters))
                mask = kdf.GetBytes(length);
            Array.Clear(password, 0, password.Length);
            return mask;
        }

        private void ReplaceCctor(ModuleDef module, TypeDef helper,
            FieldDef fName, FieldDef fLock,
            FieldDef fMh, FieldDef fDh,
            FieldDef fFh, FieldDef fFdh,
            FieldDef fTh, FieldDef fUs,
            FieldDef fPepper, FieldDef fIters,
            byte[] pepperBytes, int itersValue,
            string resName)
        {
            MethodDef cctor = helper.FindStaticConstructor();
            if (cctor == null)
            {
                cctor = new MethodDefUser(".cctor",
                    MethodSig.CreateStatic(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                    DnMethodAttributes.RTSpecialName);
                helper.Methods.Add(cctor);
                engine.injectedMethods.Add(cctor);
            }
            cctor.Body = new CilBody();
            var il = cctor.Body.Instructions;

            var importer = new Importer(module);
            ITypeDefOrRef rmh = importer.Import(typeof(RuntimeMethodHandle));
            ITypeDefOrRef rfh = importer.Import(typeof(RuntimeFieldHandle));
            ITypeDefOrRef rth = importer.Import(typeof(RuntimeTypeHandle));
            ITypeDefOrRef str = module.CorLibTypes.String.TypeDefOrRef;

            ITypeDefOrRef sysException = importer.Import(typeof(System.Exception));

            var outerTryStart = Instruction.Create(DnOpCodes.Ldstr, resName);
            il.Add(outerTryStart);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fName));

            il.Add(engine.LoadInt(itersValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fIters));

            EmitInitPepper(module, helper, il, fPepper, pepperBytes);

            if (fLock != null)
            {
                var objCtor = new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    module.CorLibTypes.Object.TypeDefOrRef);
                il.Add(Instruction.Create(DnOpCodes.Newobj, objCtor));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, fLock));
            }

            EmitInitMethodArray(module, helper, cctor, sysException, fMh, rmh, importMethods);
            EmitInitTypeArray  (module, helper, cctor, sysException, fDh, rth, importMethodDeclTypes);

            EmitInitFieldArray (module, helper, cctor, sysException, fFh,  rfh, importFields);
            EmitInitTypeArray  (module, helper, cctor, sysException, fFdh, rth, importFieldDeclTypes);

            EmitInitTypeArray(module, helper, cctor, sysException, fTh, rth, importTypes);

            EmitInitStringArray(module, helper, cctor, sysException, fUs, str, importStrings);

            var retOk           = Instruction.Create(DnOpCodes.Ret);
            var outerLeaveOk    = Instruction.Create(DnOpCodes.Leave, retOk);
            il.Add(outerLeaveOk);

            var outerCatchPop   = Instruction.Create(DnOpCodes.Pop);
            il.Add(outerCatchPop);
            il.Add(Instruction.Create(DnOpCodes.Leave, retOk));
            il.Add(retOk);

            var outerEh = new ExceptionHandler(ExceptionHandlerType.Catch);
            outerEh.TryStart     = outerTryStart;
            outerEh.TryEnd       = outerCatchPop;
            outerEh.HandlerStart = outerCatchPop;
            outerEh.HandlerEnd   = retOk;
            outerEh.CatchType    = sysException;
            cctor.Body.ExceptionHandlers.Add(outerEh);

            cctor.Body.KeepOldMaxStack = false;
        }

        private void EmitInitPepper(ModuleDef module, TypeDef helper,
            IList<Instruction> il, FieldDef fPepper, byte[] pepperBytes)
        {
            var importer = new Importer(module);
            ITypeDefOrRef sysValueType = importer.Import(typeof(ValueType));
            ITypeDefOrRef sysByte      = importer.Import(typeof(byte));
            IMethod rhInitArr = importer.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers)
                .GetMethod("InitializeArray",
                    new Type[] { typeof(Array), typeof(RuntimeFieldHandle) }));

            string holderName = engine.MakeName();
            TypeDef holder = new TypeDefUser("", holderName, sysValueType);
            holder.Attributes = DnTypeAttributes.NestedPrivate
                              | DnTypeAttributes.SequentialLayout
                              | DnTypeAttributes.Sealed;
            holder.ClassLayout = new ClassLayoutUser(1, (uint)pepperBytes.Length);
            helper.NestedTypes.Add(holder);
            engine.injectedTypes.Add(holder);

            FieldDef rvaField = new FieldDefUser(engine.MakeName(),
                new FieldSig(holder.ToTypeSig()),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static
                | DnFieldAttributes.HasFieldRVA);
            rvaField.HasFieldRVA = true;
            rvaField.InitialValue = (byte[])pepperBytes.Clone();
            helper.Fields.Add(rvaField);

            il.Add(engine.LoadInt(pepperBytes.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, sysByte));
            il.Add(Instruction.Create(DnOpCodes.Dup));
            il.Add(Instruction.Create(DnOpCodes.Ldtoken, rvaField));
            il.Add(Instruction.Create(DnOpCodes.Call, rhInitArr));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fPepper));
        }

        private void EmitResilientLdtokenStore(MethodDef target,
            ITypeDefOrRef sysException, FieldDef arr, ITypeDefOrRef element,
            int index, IFullName operandIfMethod, IFullName operandIfField,
            ITypeDefOrRef operandIfType)
        {
            var il = target.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Ldsfld, arr);
            il.Add(tryStart);
            il.Add(engine.LoadInt(index));
            if (operandIfMethod != null)
                il.Add(Instruction.Create(DnOpCodes.Ldtoken, (IMethod)operandIfMethod));
            else if (operandIfField != null)
                il.Add(Instruction.Create(DnOpCodes.Ldtoken, (IField)operandIfField));
            else
                il.Add(Instruction.Create(DnOpCodes.Ldtoken, operandIfType));
            il.Add(Instruction.Create(DnOpCodes.Stelem, element));

            var afterCatch = Instruction.Create(DnOpCodes.Nop);
            var leaveOk    = Instruction.Create(DnOpCodes.Leave, afterCatch);
            il.Add(leaveOk);

            var catchPop   = Instruction.Create(DnOpCodes.Pop);
            il.Add(catchPop);
            il.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));
            il.Add(afterCatch);

            var eh = new ExceptionHandler(ExceptionHandlerType.Catch);
            eh.TryStart     = tryStart;
            eh.TryEnd       = catchPop;
            eh.HandlerStart = catchPop;
            eh.HandlerEnd   = afterCatch;
            eh.CatchType    = sysException;
            target.Body.ExceptionHandlers.Add(eh);
        }

        private MethodDef CreatePopulatorAndCallFromCctor(ModuleDef module,
            TypeDef helper, MethodDef cctor, ITypeDefOrRef sysException)
        {
            var pop = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static |
                DnMethodAttributes.HideBySig);
            pop.Body = new CilBody();
            helper.Methods.Add(pop);
            engine.injectedMethods.Add(pop);

            var cIl = cctor.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Call, pop);
            cIl.Add(tryStart);

            var afterCatch = Instruction.Create(DnOpCodes.Nop);
            cIl.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

            var catchPop = Instruction.Create(DnOpCodes.Pop);
            cIl.Add(catchPop);
            cIl.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));
            cIl.Add(afterCatch);

            var eh = new ExceptionHandler(ExceptionHandlerType.Catch);
            eh.TryStart     = tryStart;
            eh.TryEnd       = catchPop;
            eh.HandlerStart = catchPop;
            eh.HandlerEnd   = afterCatch;
            eh.CatchType    = sysException;
            cctor.Body.ExceptionHandlers.Add(eh);

            return pop;
        }

        private const int PopulatorChunkSizeRisky = 1;
        private const int PopulatorChunkSize = 16;

        private void EmitInitMethodArray(ModuleDef module, TypeDef helper,
            MethodDef cctor, ITypeDefOrRef sysException,
            FieldDef arr, ITypeDefOrRef element, List<IMethod> imports)
        {

            var cIl = cctor.Body.Instructions;
            cIl.Add(engine.LoadInt(imports.Count));
            cIl.Add(Instruction.Create(DnOpCodes.Newarr, element));
            cIl.Add(Instruction.Create(DnOpCodes.Stsfld, arr));

            int n = imports.Count;
            for (int chunkStart = 0; chunkStart < n; chunkStart += PopulatorChunkSizeRisky)
            {
                int chunkEnd = System.Math.Min(chunkStart + PopulatorChunkSizeRisky, n);
                var pop = CreatePopulatorAndCallFromCctor(module, helper, cctor, sysException);
                for (int i = chunkStart; i < chunkEnd; i++)
                    EmitResilientLdtokenStore(pop, sysException, arr, element,
                        i, imports[i], null, null);
                pop.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            }

            if (n == 0)
            {
                var pop = CreatePopulatorAndCallFromCctor(module, helper, cctor, sysException);
                pop.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            }
        }

        private void EmitInitFieldArray(ModuleDef module, TypeDef helper,
            MethodDef cctor, ITypeDefOrRef sysException,
            FieldDef arr, ITypeDefOrRef element, List<IField> imports)
        {
            var cIl = cctor.Body.Instructions;
            cIl.Add(engine.LoadInt(imports.Count));
            cIl.Add(Instruction.Create(DnOpCodes.Newarr, element));
            cIl.Add(Instruction.Create(DnOpCodes.Stsfld, arr));

            int n = imports.Count;
            for (int chunkStart = 0; chunkStart < n; chunkStart += PopulatorChunkSize)
            {
                int chunkEnd = System.Math.Min(chunkStart + PopulatorChunkSize, n);
                var pop = CreatePopulatorAndCallFromCctor(module, helper, cctor, sysException);
                for (int i = chunkStart; i < chunkEnd; i++)
                    EmitResilientLdtokenStore(pop, sysException, arr, element,
                        i, null, imports[i], null);
                pop.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            }
            if (n == 0)
            {
                var pop = CreatePopulatorAndCallFromCctor(module, helper, cctor, sysException);
                pop.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            }
        }

        private void EmitInitTypeArray(ModuleDef module, TypeDef helper,
            MethodDef cctor, ITypeDefOrRef sysException,
            FieldDef arr, ITypeDefOrRef element, List<ITypeDefOrRef> imports)
        {
            var cIl = cctor.Body.Instructions;
            cIl.Add(engine.LoadInt(imports.Count));
            cIl.Add(Instruction.Create(DnOpCodes.Newarr, element));
            cIl.Add(Instruction.Create(DnOpCodes.Stsfld, arr));

            int n = imports.Count;
            for (int chunkStart = 0; chunkStart < n; chunkStart += PopulatorChunkSizeRisky)
            {
                int chunkEnd = System.Math.Min(chunkStart + PopulatorChunkSizeRisky, n);
                var pop = CreatePopulatorAndCallFromCctor(module, helper, cctor, sysException);
                for (int i = chunkStart; i < chunkEnd; i++)
                    EmitResilientLdtokenStore(pop, sysException, arr, element,
                        i, null, null, imports[i]);
                pop.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            }
            if (n == 0)
            {
                var pop = CreatePopulatorAndCallFromCctor(module, helper, cctor, sysException);
                pop.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            }
        }

        private void EmitInitStringArray(ModuleDef module, TypeDef helper,
            MethodDef cctor, ITypeDefOrRef sysException,
            FieldDef arr, ITypeDefOrRef element, List<string> imports)
        {
            var cIl = cctor.Body.Instructions;
            cIl.Add(engine.LoadInt(imports.Count));
            cIl.Add(Instruction.Create(DnOpCodes.Newarr, element));
            cIl.Add(Instruction.Create(DnOpCodes.Stsfld, arr));

            int n = imports.Count;
            for (int chunkStart = 0; chunkStart < n; chunkStart += PopulatorChunkSize)
            {
                int chunkEnd = System.Math.Min(chunkStart + PopulatorChunkSize, n);
                var pop = CreatePopulatorAndCallFromCctor(module, helper, cctor, sysException);
                var pIl = pop.Body.Instructions;
                for (int i = chunkStart; i < chunkEnd; i++)
                {
                    var tryStart = Instruction.Create(DnOpCodes.Ldsfld, arr);
                    pIl.Add(tryStart);
                    pIl.Add(engine.LoadInt(i));
                    pIl.Add(Instruction.Create(DnOpCodes.Ldstr, imports[i]));
                    pIl.Add(Instruction.Create(DnOpCodes.Stelem_Ref));

                    var afterCatch = Instruction.Create(DnOpCodes.Nop);
                    pIl.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

                    var catchPop = Instruction.Create(DnOpCodes.Pop);
                    pIl.Add(catchPop);
                    pIl.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));
                    pIl.Add(afterCatch);

                    var eh = new ExceptionHandler(ExceptionHandlerType.Catch);
                    eh.TryStart     = tryStart;
                    eh.TryEnd       = catchPop;
                    eh.HandlerStart = catchPop;
                    eh.HandlerEnd   = afterCatch;
                    eh.CatchType    = sysException;
                    pop.Body.ExceptionHandlers.Add(eh);
                }
                pIl.Add(Instruction.Create(DnOpCodes.Ret));
            }
            if (n == 0)
            {
                var pop = CreatePopulatorAndCallFromCctor(module, helper, cctor, sysException);
                pop.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            }
        }

        private void BuildStub(MethodDef m, int idx, MethodDef runMethod, ModuleDef module)
        {
            int argCount = m.Parameters.Count;
            bool hasByRef = false;
            for (int i = 0; i < argCount; i++)
            {
                TypeSig pt = m.Parameters[i].Type;
                if (pt == null) continue;
                if (pt.RemovePinnedAndModifiers() is ByRefSig) { hasByRef = true; break; }
            }

            if (!hasByRef)
            {
                BuildStubSimple(m, idx, runMethod, module);
                return;
            }

            BuildStubWithByRef(m, idx, runMethod, module);
        }

        private void BuildStubSimple(MethodDef m, int idx, MethodDef runMethod, ModuleDef module)
        {
            CilBody body = new CilBody();
            var il = body.Instructions;
            int argCount = m.Parameters.Count;

            il.Add(engine.LoadInt(idx));
            il.Add(Instruction.Create(DnOpCodes.Ldtoken, m));
            il.Add(engine.LoadInt(argCount));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Object.TypeDefOrRef));
            for (int i = 0; i < argCount; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(engine.LoadInt(i));
                EmitLoadArg(il, m, i);
                if (m.Parameters[i].Type.IsValueType)
                    il.Add(Instruction.Create(DnOpCodes.Box,
                        m.Parameters[i].Type.ToTypeDefOrRef()));
                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }

            il.Add(Instruction.Create(DnOpCodes.Call, runMethod));

            TypeSig ret = m.MethodSig.RetType;
            if (ret.ElementType == ElementType.Void)
                il.Add(Instruction.Create(DnOpCodes.Pop));
            else if (ret.IsValueType)
                il.Add(Instruction.Create(DnOpCodes.Unbox_Any, ret.ToTypeDefOrRef()));
            else
                il.Add(Instruction.Create(DnOpCodes.Castclass, ret.ToTypeDefOrRef()));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            body.MaxStack = 8;
            body.InitLocals = false;
            body.Variables.Clear();
            body.ExceptionHandlers.Clear();
            m.Body = body;

        }

        private void BuildStubWithByRef(MethodDef m, int idx, MethodDef runMethod, ModuleDef module)
        {
            CilBody body = new CilBody();
            body.InitLocals = true;
            var il = body.Instructions;
            int argCount = m.Parameters.Count;
            TypeSig ret = m.MethodSig.RetType;

            Local argsLocal = new Local(new SZArraySig(module.CorLibTypes.Object));
            body.Variables.Add(argsLocal);
            Local retLocal = null;
            if (ret.ElementType != ElementType.Void)
            {
                retLocal = new Local(ret);
                body.Variables.Add(retLocal);
            }

            il.Add(engine.LoadInt(argCount));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Object.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, argsLocal));

            for (int i = 0; i < argCount; i++)
            {
                TypeSig pt = m.Parameters[i].Type.RemovePinnedAndModifiers();
                ByRefSig brs = pt as ByRefSig;

                il.Add(Instruction.Create(DnOpCodes.Ldloc, argsLocal));
                il.Add(engine.LoadInt(i));
                EmitLoadArg(il, m, i);

                if (brs != null)
                {
                    TypeSig inner = brs.Next.RemovePinnedAndModifiers();
                    if (inner.IsValueType)
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldobj, inner.ToTypeDefOrRef()));
                        il.Add(Instruction.Create(DnOpCodes.Box, inner.ToTypeDefOrRef()));
                    }
                    else
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldind_Ref));
                    }
                }
                else if (pt.IsValueType)
                {
                    il.Add(Instruction.Create(DnOpCodes.Box, pt.ToTypeDefOrRef()));
                }

                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }

            il.Add(engine.LoadInt(idx));
            il.Add(Instruction.Create(DnOpCodes.Ldtoken, m));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, argsLocal));
            il.Add(Instruction.Create(DnOpCodes.Call, runMethod));

            if (ret.ElementType == ElementType.Void)
            {
                il.Add(Instruction.Create(DnOpCodes.Pop));
            }
            else
            {
                if (ret.IsValueType)
                    il.Add(Instruction.Create(DnOpCodes.Unbox_Any, ret.ToTypeDefOrRef()));
                else
                    il.Add(Instruction.Create(DnOpCodes.Castclass, ret.ToTypeDefOrRef()));
                il.Add(Instruction.Create(DnOpCodes.Stloc, retLocal));
            }

            for (int i = 0; i < argCount; i++)
            {
                TypeSig pt = m.Parameters[i].Type.RemovePinnedAndModifiers();
                ByRefSig brs = pt as ByRefSig;
                if (brs == null) continue;

                TypeSig inner = brs.Next.RemovePinnedAndModifiers();
                EmitLoadArg(il, m, i);
                il.Add(Instruction.Create(DnOpCodes.Ldloc, argsLocal));
                il.Add(engine.LoadInt(i));
                il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));

                if (inner.IsValueType)
                {
                    il.Add(Instruction.Create(DnOpCodes.Unbox_Any, inner.ToTypeDefOrRef()));
                    il.Add(Instruction.Create(DnOpCodes.Stobj, inner.ToTypeDefOrRef()));
                }
                else
                {
                    il.Add(Instruction.Create(DnOpCodes.Castclass, inner.ToTypeDefOrRef()));
                    il.Add(Instruction.Create(DnOpCodes.Stind_Ref));
                }
            }

            if (ret.ElementType != ElementType.Void)
                il.Add(Instruction.Create(DnOpCodes.Ldloc, retLocal));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            body.MaxStack = 16;
            body.ExceptionHandlers.Clear();
            m.Body = body;

        }

        internal void ApplyLatePoison(ModuleDef module)
        {
            foreach (var stub in engine.bodyVaultedStubs)
            {
                if (stub == null || stub.Body == null) continue;

                if (stub.Body.HasExceptionHandlers && stub.Body.ExceptionHandlers.Count > 0)
                    continue;

                if (stub.DeclaringType != null && engine.IsWinFormsType(stub.DeclaringType))
                    continue;
                AppendUnreachableEhPoison(stub, stub.Body, module);
            }
        }

        private void AppendUnreachableEhPoison(MethodDef m, CilBody body, ModuleDef module)
        {
            try
            {
                var il = body.Instructions;
                if (il.Count == 0) return;

                Instruction realStart = il[0];
                Instruction deadTry    = Instruction.Create(DnOpCodes.Nop);
                Instruction deadHandlr = Instruction.Create(DnOpCodes.Add);
                Instruction br         = Instruction.Create(DnOpCodes.Br_S, realStart);

                il.Insert(0, br);
                il.Insert(1, deadTry);
                il.Insert(2, Instruction.Create(DnOpCodes.Leave_S, realStart));
                il.Insert(3, deadHandlr);
                il.Insert(4, Instruction.Create(DnOpCodes.Pop));
                il.Insert(5, Instruction.Create(DnOpCodes.Leave_S, realStart));

                body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                {
                    TryStart     = deadTry,
                    TryEnd       = deadHandlr,
                    HandlerStart = deadHandlr,
                    HandlerEnd   = realStart,
                    CatchType    = module.CorLibTypes.Object.TypeDefOrRef
                });

                body.KeepOldMaxStack = true;
            }
            catch
            {

            }
        }

        private void EmitLoadArg(IList<Instruction> il, MethodDef m, int paramIdx)
        {
            switch (paramIdx)
            {
                case 0: il.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                case 1: il.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                case 2: il.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                case 3: il.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                default:
                    if (paramIdx < 256)
                        il.Add(Instruction.Create(DnOpCodes.Ldarg_S, m.Parameters[paramIdx]));
                    else
                        il.Add(Instruction.Create(DnOpCodes.Ldarg, m.Parameters[paramIdx]));
                    break;
            }
        }

        private static void WriteInt32(byte[] b, int o, int v)
        {
            b[o]     = (byte)(v       & 0xFF);
            b[o + 1] = (byte)((v >> 8) & 0xFF);
            b[o + 2] = (byte)((v >> 16) & 0xFF);
            b[o + 3] = (byte)((v >> 24) & 0xFF);
        }

        private static void WriteInt64(byte[] b, int o, long v)
        {
            for (int i = 0; i < 8; i++) b[o + i] = (byte)((v >> (8 * i)) & 0xFF);
        }

        private static void WriteFloat32(byte[] b, int o, float v)
        {
            byte[] tmp = BitConverter.GetBytes(v);
            Buffer.BlockCopy(tmp, 0, b, o, 4);
        }

        private static void WriteFloat64(byte[] b, int o, double v)
        {
            byte[] tmp = BitConverter.GetBytes(v);
            Buffer.BlockCopy(tmp, 0, b, o, 8);
        }
    }
}

