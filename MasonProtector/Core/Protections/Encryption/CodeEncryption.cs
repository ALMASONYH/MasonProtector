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

    internal class CodeEncryptionProtection
    {
        private Obfuscation engine;

        internal CodeEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
        }

        internal void ApplyCodeEncryption(ModuleDef module)
        {

            var vaultType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vaultType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(vaultType);
            engine.injectedTypes.Add(vaultType);

            IMethod assertM = null;
            try
            {
                assertM = module.Import(typeof(System.Diagnostics.Debug)
                    .GetMethod("Assert", new Type[] { typeof(bool) }));
            }
            catch { assertM = null; }

            var cache = new Dictionary<string, MethodDef>();

            foreach (TypeDef type in module.GetTypes())
            {
                if (type == vaultType) continue;
                if (engine.IsCompilerGenerated(type)) continue;
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {

                    if (!IsEligible(method)) continue;
                    if (engine.MethodHasAsyncOrIteratorAttribute(method)) continue;
                    try { WrapCallsInMethod(module, method, vaultType, assertM, cache); }
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

        private void WrapCallsInMethod(ModuleDef module, MethodDef method,
            TypeDef vaultType, IMethod assertM, Dictionary<string, MethodDef> cache)
        {
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
                if (mdCheck != null)
                {
                    if (engine.injectedMethods.Contains(mdCheck)) continue;

                    bool isAccessible = mdCheck.IsPublic ||
                        mdCheck.IsAssembly || mdCheck.IsFamilyOrAssembly;
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
                MethodDef helper;
                if (!cache.TryGetValue(cacheKey, out helper))
                {
                    helper = BuildHelper(module, vaultType, target, isNewObj, assertM);
                    if (helper == null) continue;
                    cache[cacheKey] = helper;
                    vaultType.Methods.Add(helper);
                    engine.injectedMethods.Add(helper);
                }

                il[i].OpCode = DnOpCodes.Call;
                il[i].Operand = helper;
            }
        }

        private MethodDef BuildHelper(ModuleDef module, TypeDef vaultType,
            IMethod target, bool isNewObj, IMethod assertM)
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

            var helperSig = MethodSig.CreateStatic(retType, targetSig.Params.ToArray());
            var helper = new MethodDefUser(engine.MakeName(), helperSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed |
                DnMethodImplAttributes.NoInlining,
                DnMethodAttributes.Public | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            helper.Body = new CilBody();
            var hil = helper.Body.Instructions;

            if (assertM != null)
            {
                hil.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                hil.Add(Instruction.Create(DnOpCodes.Call, assertM));
            }

            for (int i = 0; i < targetSig.Params.Count; i++)
            {
                switch (i)
                {
                    case 0: hil.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                    case 1: hil.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                    case 2: hil.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                    case 3: hil.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                }
            }

            hil.Add(Instruction.Create(
                isNewObj ? DnOpCodes.Newobj : DnOpCodes.Call,
                module.Import(target)));
            hil.Add(Instruction.Create(DnOpCodes.Ret));

            return helper;
        }
    }
}
