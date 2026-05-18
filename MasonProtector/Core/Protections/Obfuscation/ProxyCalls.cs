using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class ProxyCallsProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal ProxyCallsProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyProxyCalls(ModuleDef module)
        {
            const int HOST_COUNT = 12;
            var hosts = new TypeDef[HOST_COUNT];
            for (int h = 0; h < HOST_COUNT; h++)
            {
                var pt = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                pt.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(pt);
                engine.injectedTypes.Add(pt);
                hosts[h] = pt;

                for (int f = 0; f < rng.Next(6, 14); f++)
                {
                    pt.Fields.Add(new dnlib.DotNet.FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        dnlib.DotNet.FieldAttributes.Private | dnlib.DotNet.FieldAttributes.Static));
                }
            }

            var delegateCache = new Dictionary<string, MethodDef>();
            int hostPtr = 0;

            bool allowDesigner = engine.cfg != null && engine.cfg.MaximumEncryption;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method, allowDesigner)) continue;
                    if (engine.MethodHasAsyncOrIteratorAttribute(method)) continue;
                    try { ProxyMethodCalls(module, method, hosts, ref hostPtr, delegateCache); } catch { }
                }
            }

            int totalFakes = HOST_COUNT * 5;
            for (int i = 0; i < totalFakes; i++)
            {
                var host = hosts[i % HOST_COUNT];
                var fake = BuildFakeProxy(module);
                host.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }
        }

        private MethodDef BuildFakeProxy(ModuleDef module)
        {
            int paramCount = rng.Next(0, 5);
            var paramTypes = new TypeSig[paramCount];
            for (int i = 0; i < paramCount; i++)
            {
                switch (rng.Next(0, 4))
                {
                    case 0: paramTypes[i] = module.CorLibTypes.Int32; break;
                    case 1: paramTypes[i] = module.CorLibTypes.String; break;
                    case 2: paramTypes[i] = module.CorLibTypes.Object; break;
                    default: paramTypes[i] = module.CorLibTypes.Boolean; break;
                }
            }
            TypeSig retType;
            switch (rng.Next(0, 4))
            {
                case 0: retType = module.CorLibTypes.Int32; break;
                case 1: retType = module.CorLibTypes.Void; break;
                case 2: retType = module.CorLibTypes.Object; break;
                default: retType = module.CorLibTypes.Boolean; break;
            }
            var m = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(retType, paramTypes),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            var fil = m.Body.Instructions;
            if (retType == module.CorLibTypes.Void)
                fil.Add(Instruction.Create(DnOpCodes.Ret));
            else if (retType == module.CorLibTypes.Int32 || retType == module.CorLibTypes.Boolean)
            {
                fil.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                fil.Add(Instruction.Create(DnOpCodes.Ret));
            }
            else
            {
                fil.Add(Instruction.Create(DnOpCodes.Ldnull));
                fil.Add(Instruction.Create(DnOpCodes.Ret));
            }
            return m;
        }

        private void ProxyMethodCalls(ModuleDef module, MethodDef method, TypeDef[] hosts,
            ref int hostPtr, Dictionary<string, MethodDef> cache)
        {
            bool maxEnc = engine.cfg != null && engine.cfg.MaximumEncryption;
            var il = method.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {

                bool isCall   = il[i].OpCode == DnOpCodes.Call;
                bool isNewObj = il[i].OpCode == DnOpCodes.Newobj;
                if (!isCall && !isNewObj) continue;

                var target = il[i].Operand as IMethod;
                if (target == null) continue;
                if (engine.IsCompilerInfrastructureCall(target)) continue;
                MethodDef mdCheck = target as MethodDef;
                if (mdCheck != null && engine.injectedMethods.Contains(mdCheck)) continue;

                if (mdCheck != null)
                {
                    bool isAccessible = mdCheck.IsPublic ||
                        (mdCheck.IsAssembly || mdCheck.IsFamilyOrAssembly);
                    if (!isAccessible) continue;
                }

                var targetSig = target.MethodSig;
                if (targetSig == null) continue;

                if (isCall && targetSig.HasThis) continue;
                if (targetSig.Params.Count > 4) continue;
                if (targetSig.GenParamCount > 0) continue;

                if (isNewObj && !engine.IsConfirmedReferenceTypeCtor(target.DeclaringType))
                    continue;

                string cacheKey = (isNewObj ? "NEW:" : "CALL:") + target.FullName;
                MethodDef proxy;
                if (!cache.TryGetValue(cacheKey, out proxy))
                {
                    var host = hosts[hostPtr % hosts.Length];
                    hostPtr++;
                    proxy = BuildProxyMethod(module, target, host, isNewObj, maxEnc);
                    if (proxy == null) continue;
                    cache[cacheKey] = proxy;
                    host.Methods.Add(proxy);
                    engine.injectedMethods.Add(proxy);
                }

                il[i].OpCode = DnOpCodes.Call;
                il[i].Operand = proxy;
            }
        }

        private MethodDef BuildProxyMethod(ModuleDef module, IMethod target,
            TypeDef proxyType, bool isNewObj, bool maxEnc)
        {
            var targetSig = target.MethodSig;
            if (targetSig == null) return null;

            TypeSig retType;
            if (isNewObj)
            {
                if (target.DeclaringType == null) return null;
                try
                {
                    var imported = module.Import(target.DeclaringType);
                    var asDefOrRef = imported as ITypeDefOrRef;
                    if (asDefOrRef == null) return null;
                    retType = asDefOrRef.ToTypeSig();
                }
                catch { return null; }
                if (retType == null) return null;
            }
            else
            {
                retType = targetSig.RetType;
            }

            var proxySig = MethodSig.CreateStatic(
                retType,
                targetSig.Params.ToArray());

            var implFlags = DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed |
                            DnMethodImplAttributes.NoInlining;
            var attrFlags = maxEnc
                ? (DnMethodAttributes.Public | DnMethodAttributes.Static | DnMethodAttributes.HideBySig)
                : (DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            var proxy = new MethodDefUser(engine.MakeName(),
                proxySig, implFlags, attrFlags);

            proxy.Body = new CilBody();
            var il = proxy.Body.Instructions;

            if (maxEnc)
            {
                try
                {
                    var assertM = module.Import(typeof(System.Diagnostics.Debug)
                        .GetMethod("Assert", new Type[] { typeof(bool) }));
                    if (assertM != null)
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                        il.Add(Instruction.Create(DnOpCodes.Call, assertM));
                    }
                }
                catch { }
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

            il.Add(Instruction.Create(
                isNewObj ? DnOpCodes.Newobj : DnOpCodes.Call,
                module.Import(target)));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return proxy;
        }
    }
}

