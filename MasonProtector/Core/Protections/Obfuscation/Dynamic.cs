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

    internal class DynamicProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal DynamicProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyDynamic(ModuleDef module, TypeDef modType)
        {

            var dispatchType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            dispatchType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(dispatchType);
            engine.injectedTypes.Add(dispatchType);

            var cache = new Dictionary<string, MethodDef>();

            foreach (TypeDef type in module.GetTypes())
            {
                if (type == dispatchType) continue;
                if (engine.IsCompilerGenerated(type)) continue;
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {

                    if (!IsEligible(method)) continue;
                    if (engine.MethodHasAsyncOrIteratorAttribute(method)) continue;
                    try { RewriteMethod(module, method, dispatchType, cache); }
                    catch { }
                }
            }
        }

        private bool IsEligible(MethodDef m)
        {
            if (m == null) return false;
            if (!m.HasBody || !m.Body.HasInstructions) return false;
            if (engine.injectedMethods.Contains(m)) return false;
            if (engine.IsMethodUserExcluded(m)) return false;
            if (m.IsRuntimeSpecialName && !m.IsStaticConstructor) return false;
            if (m.HasGenericParameters) return false;
            if (m.DeclaringType != null && m.DeclaringType.HasGenericParameters) return false;
            if (m.Name == "Create__Instance__" || m.Name == "Dispose__Instance__") return false;
            return true;
        }

        private void RewriteMethod(ModuleDef module, MethodDef method,
            TypeDef dispatchType, Dictionary<string, MethodDef> cache)
        {
            var il = method.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode != DnOpCodes.Call) continue;

                var target = il[i].Operand as IMethod;
                if (target == null) continue;
                if (engine.IsCompilerInfrastructureCall(target)) continue;
                MethodDef mdCheck = target as MethodDef;
                if (mdCheck != null && engine.injectedMethods.Contains(mdCheck)) continue;

                var targetSig = target.MethodSig;
                if (targetSig == null) continue;
                if (targetSig.HasThis) continue;
                if (targetSig.Params.Count > 4) continue;
                if (targetSig.GenParamCount > 0) continue;

                if (target.DeclaringType != null)
                {
                    var dn = target.DeclaringType.FullName;
                    if (dn == "System.RuntimeMethodHandle" || dn == "System.RuntimeTypeHandle") continue;
                }

                string cacheKey = target.FullName;
                MethodDef proxy;
                if (!cache.TryGetValue(cacheKey, out proxy))
                {
                    proxy = BuildCalliProxy(module, dispatchType, target);
                    if (proxy == null) continue;
                    cache[cacheKey] = proxy;
                }

                il[i].Operand = proxy;
            }
        }

        private MethodDef BuildCalliProxy(ModuleDef module, TypeDef dispatchType, IMethod target)
        {
            var targetSig = target.MethodSig;
            if (targetSig == null) return null;

            var ptrField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.IntPtr),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            dispatchType.Fields.Add(ptrField);

            var proxySig = MethodSig.CreateStatic(targetSig.RetType, targetSig.Params.ToArray());
            var proxy = new MethodDefUser(engine.MakeName(), proxySig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed |
                DnMethodImplAttributes.NoInlining,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            proxy.Body = new CilBody();
            proxy.Body.InitLocals = true;

            proxy.Body.Variables.Add(new Local(module.CorLibTypes.IntPtr));
            var pil = proxy.Body.Instructions;

            pil.Add(Instruction.Create(DnOpCodes.Ldsfld, ptrField));
            pil.Add(Instruction.Create(DnOpCodes.Stloc_0));

            Instruction haveFp = Instruction.Create(DnOpCodes.Nop);
            pil.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            pil.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            pil.Add(Instruction.Create(DnOpCodes.Conv_I));
            pil.Add(Instruction.Create(DnOpCodes.Bne_Un, haveFp));

            pil.Add(Instruction.Create(DnOpCodes.Ldftn, module.Import(target)));
            pil.Add(Instruction.Create(DnOpCodes.Stloc_0));
            pil.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            pil.Add(Instruction.Create(DnOpCodes.Stsfld, ptrField));

            pil.Add(haveFp);

            for (int i = 0; i < targetSig.Params.Count; i++)
            {
                switch (i)
                {
                    case 0: pil.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                    case 1: pil.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                    case 2: pil.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                    case 3: pil.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                }
            }

            pil.Add(Instruction.Create(DnOpCodes.Ldloc_0));

            var calliSig = MethodSig.CreateStatic(targetSig.RetType, targetSig.Params.ToArray());
            calliSig.CallingConvention = CallingConvention.Default;
            pil.Add(new Instruction(DnOpCodes.Calli, calliSig));

            pil.Add(Instruction.Create(DnOpCodes.Ret));

            dispatchType.Methods.Add(proxy);
            engine.injectedMethods.Add(proxy);
            return proxy;
        }
    }
}
