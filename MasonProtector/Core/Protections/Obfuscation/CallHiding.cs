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
    internal class CallHidingProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int TRAMPOLINE_POOL = 18;
        private List<TypeDef> trampolineTypes;
        private Dictionary<string, MethodDef> trampolineCache;
        private int trampolineCount;

        internal CallHidingProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyCallHiding(ModuleDef module)
        {
            trampolineTypes = new List<TypeDef>();
            trampolineCache = new Dictionary<string, MethodDef>();
            trampolineCount = 0;

            for (int i = 0; i < TRAMPOLINE_POOL; i++)
            {
                var trampType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                trampType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(trampType);
                engine.injectedTypes.Add(trampType);

                for (int d = 0; d < rng.Next(6, 14); d++)
                {
                    trampType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int f = 0; f < rng.Next(4, 10); f++)
                {
                    var fakeMethod = BuildFakeTrampoline(module);
                    trampType.Methods.Add(fakeMethod);
                    engine.injectedMethods.Add(fakeMethod);
                }

                trampolineTypes.Add(trampType);
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (engine.MethodHasAsyncOrIteratorAttribute(method)) continue;
                    try
                    {
                        HideMethodCalls(module, method);
                    }
                    catch { }
                }
            }
        }

        private void HideMethodCalls(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode != DnOpCodes.Call) continue;

                var target = il[i].Operand as IMethod;
                if (target == null) continue;
                if (engine.IsCompilerInfrastructureCall(target)) continue;
                MethodDef mdTarget = target as MethodDef;
                if (mdTarget != null && engine.injectedMethods.Contains(mdTarget)) continue;

                if (mdTarget != null)
                {
                    bool isAccessible = mdTarget.IsPublic ||
                        mdTarget.IsAssembly || mdTarget.IsFamilyOrAssembly;
                    if (!isAccessible) continue;
                }

                var sig = target.MethodSig;
                if (sig == null || sig.HasThis) continue;
                if (sig.Params.Count > 3) continue;
                if (sig.GenParamCount > 0) continue;

                if (rng.Next(0, 5) == 0) continue;

                string key = "CH:" + target.FullName;
                MethodDef trampoline;
                if (!trampolineCache.TryGetValue(key, out trampoline))
                {
                    trampoline = BuildTrampoline(module, target);
                    if (trampoline == null) continue;

                    var host = trampolineTypes[trampolineCount % TRAMPOLINE_POOL];
                    host.Methods.Add(trampoline);
                    engine.injectedMethods.Add(trampoline);
                    trampolineCache[key] = trampoline;
                    trampolineCount++;
                }

                il[i].Operand = trampoline;
            }
        }

        private MethodDef BuildTrampoline(ModuleDef module, IMethod target)
        {
            var sig = target.MethodSig;
            if (sig == null) return null;

            var trampolineSig = MethodSig.CreateStatic(sig.RetType, sig.Params.ToArray());
            var method = new MethodDefUser(engine.MakeName(),
                trampolineSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            var il = method.Body.Instructions;

            int junkPattern = rng.Next(0, 6);
            switch (junkPattern)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Nop));
                    il.Add(Instruction.Create(DnOpCodes.Nop));
                    il.Add(Instruction.Create(DnOpCodes.Nop));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                default:
                    break;
            }

            bool doubleWrap = rng.Next(0, 3) == 0;

            if (doubleWrap)
            {
                var innerTramp = BuildInnerTrampoline(module, target);
                if (innerTramp != null)
                {
                    var host = trampolineTypes[trampolineCount % TRAMPOLINE_POOL];
                    host.Methods.Add(innerTramp);
                    engine.injectedMethods.Add(innerTramp);

                    for (int p = 0; p < sig.Params.Count; p++)
                    {
                        switch (p)
                        {
                            case 0: il.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                            case 1: il.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                            case 2: il.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                            case 3: il.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                        }
                    }

                    il.Add(Instruction.Create(DnOpCodes.Call, innerTramp));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    return method;
                }
            }

            for (int p = 0; p < sig.Params.Count; p++)
            {
                switch (p)
                {
                    case 0: il.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                    case 1: il.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                    case 2: il.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                    case 3: il.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Call, module.Import(target)));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildInnerTrampoline(ModuleDef module, IMethod target)
        {
            var sig = target.MethodSig;
            if (sig == null) return null;

            var innerSig = MethodSig.CreateStatic(sig.RetType, sig.Params.ToArray());
            var method = new MethodDefUser(engine.MakeName(),
                innerSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Nop));

            for (int p = 0; p < sig.Params.Count; p++)
            {
                switch (p)
                {
                    case 0: il.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                    case 1: il.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                    case 2: il.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                    case 3: il.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Call, module.Import(target)));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildFakeTrampoline(ModuleDef module)
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
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

