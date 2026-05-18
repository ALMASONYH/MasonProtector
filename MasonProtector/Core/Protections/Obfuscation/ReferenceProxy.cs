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
    internal class ReferenceProxyProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int DELEGATE_POOL_SIZE = 24;
        private List<TypeDef> proxyContainers;
        private Dictionary<string, MethodDef> proxyCache;
        private int totalProxied;

        internal ReferenceProxyProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyReferenceProxy(ModuleDef module)
        {
            proxyContainers = new List<TypeDef>();
            proxyCache = new Dictionary<string, MethodDef>();
            totalProxied = 0;

            for (int c = 0; c < DELEGATE_POOL_SIZE; c++)
            {
                var container = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                container.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(container);
                engine.injectedTypes.Add(container);

                for (int d = 0; d < rng.Next(6, 14); d++)
                {
                    container.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                proxyContainers.Add(container);
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
                        ProxyMethodReferences(module, method);
                    }
                    catch { }
                }
            }
        }

        private void ProxyMethodReferences(ModuleDef module, MethodDef method)
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

                if (mdCheck != null)
                {
                    bool isAccessible = mdCheck.IsPublic ||
                        mdCheck.IsAssembly || mdCheck.IsFamilyOrAssembly;
                    if (!isAccessible) continue;
                }

                var targetSig = target.MethodSig;
                if (targetSig == null) continue;
                if (targetSig.HasThis) continue;
                if (targetSig.GenParamCount > 0) continue;
                if (targetSig.Params.Count > 4) continue;

                string cacheKey = "RP:" + target.FullName;
                MethodDef proxy;
                if (!proxyCache.TryGetValue(cacheKey, out proxy))
                {
                    proxy = BuildStaticProxy(module, target);
                    if (proxy == null) continue;
                    proxyCache[cacheKey] = proxy;

                    var container = proxyContainers[totalProxied % DELEGATE_POOL_SIZE];
                    container.Methods.Add(proxy);
                    engine.injectedMethods.Add(proxy);
                    totalProxied++;
                }

                il[i].Operand = proxy;
            }
        }

        private MethodDef BuildStaticProxy(ModuleDef module, IMethod target)
        {
            var targetSig = target.MethodSig;
            if (targetSig == null) return null;

            var proxySig = MethodSig.CreateStatic(targetSig.RetType, targetSig.Params.ToArray());

            var proxy = new MethodDefUser(engine.MakeName(),
                proxySig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            proxy.Body = new CilBody();
            proxy.Body.InitLocals = true;
            var il = proxy.Body.Instructions;

            int scrambleType = rng.Next(0, 5);
            switch (scrambleType)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Nop));
                    il.Add(Instruction.Create(DnOpCodes.Nop));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                default:
                    break;
            }

            for (int i = 0; i < targetSig.Params.Count; i++)
            {
                switch (i)
                {
                    case 0: il.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                    case 1: il.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                    case 2: il.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                    case 3: il.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Call, module.Import(target)));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return proxy;
        }
    }
}

