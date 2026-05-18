using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{

    internal class MaxEncRelocatorProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal MaxEncRelocatorProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal int Apply(ModuleDef module)
        {
            if (engine.cfg == null || !engine.cfg.MaximumEncryption) return 0;

            var moduleType = module.GlobalType;
            if (moduleType == null) return 0;

            PromoteVisibility(module);

            int relocated = 0;
            var targets = new List<MethodDef>(engine.designerSplitSubMethods);
            foreach (var sub in targets)
            {
                try
                {
                    if (!CanRelocate(sub)) continue;
                    RelocateMethod(module, moduleType, sub);
                    relocated++;
                }
                catch {  }
            }
            return relocated;
        }

        private void PromoteVisibility(ModuleDef module)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                if (type == null) continue;
                if (type.Name == "<Module>" || type.IsGlobalModuleType) continue;
                if (engine.IsCompilerGenerated(type)) continue;
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;

                if (type.Fields != null)
                {
                    foreach (var f in type.Fields)
                    {
                        if (f == null) continue;
                        if (f.IsLiteral) continue;
                        if ((f.Attributes & DnFieldAttributes.FieldAccessMask) == DnFieldAttributes.Private)
                        {
                            f.Attributes = (f.Attributes & ~DnFieldAttributes.FieldAccessMask) | DnFieldAttributes.Assembly;
                        }
                    }
                }

                if (type.Methods != null)
                {
                    foreach (var m in type.Methods)
                    {
                        if (m == null) continue;
                        if (m.IsRuntimeSpecialName) continue;
                        if (m.IsVirtual || m.IsAbstract) continue;
                        if (m.HasOverrides) continue;
                        if ((m.Attributes & DnMethodAttributes.MemberAccessMask) == DnMethodAttributes.Private)
                        {
                            m.Attributes = (m.Attributes & ~DnMethodAttributes.MemberAccessMask) | DnMethodAttributes.Assembly;
                        }
                    }
                }
            }
        }

        private bool CanRelocate(MethodDef m)
        {
            if (m == null) return false;
            if (!m.HasBody || !m.Body.HasInstructions) return false;
            if (m.IsConstructor || m.IsStaticConstructor) return false;
            if (m.IsAbstract || m.IsVirtual) return false;
            if (m.HasOverrides) return false;
            if (m.IsRuntimeSpecialName) return false;
            if (m.IsPinvokeImpl) return false;
            if (m.HasGenericParameters) return false;
            if (m.DeclaringType == null) return false;
            if (m.DeclaringType.HasGenericParameters) return false;
            if (m.Body.HasExceptionHandlers) return false;
            if (engine.IsMethodUserExcluded(m)) return false;
            if (engine.injectedMethods.Contains(m)) return false;
            if (m.Name == "Main") return false;
            if (m.Name == ".ctor" || m.Name == ".cctor") return false;
            if (!string.IsNullOrEmpty(m.Name) && m.Name.StartsWith("<")) return false;
            return true;
        }

        private void RelocateMethod(ModuleDef module, TypeDef moduleType, MethodDef method)
        {
            bool isInstance = !method.IsStatic;
            var declTypeSig = method.DeclaringType.ToTypeSig();
            var oldSig = method.MethodSig;

            var newParams = new List<TypeSig>();
            if (isInstance) newParams.Add(declTypeSig);
            for (int i = 0; i < oldSig.Params.Count; i++)
                newParams.Add(oldSig.Params[i]);

            var newSig = MethodSig.CreateStatic(oldSig.RetType, newParams.ToArray());

            var helper = new MethodDefUser(engine.MakeName(), newSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            helper.Body = method.Body;

            foreach (var inst in helper.Body.Instructions)
            {
                var p = inst.Operand as Parameter;
                if (p != null)
                {
                    int idx = p.Index;
                    if (idx >= 0 && idx < helper.Parameters.Count)
                        inst.Operand = helper.Parameters[idx];
                }
            }

            try { helper.Body.UpdateInstructionOffsets(); } catch {  }

            moduleType.Methods.Add(helper);
            engine.injectedMethods.Add(helper);

            method.Body = new CilBody();
            method.Body.InitLocals = false;
            var il = method.Body.Instructions;
            for (int i = 0; i < method.Parameters.Count; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[i]));
            }
            il.Add(Instruction.Create(DnOpCodes.Call, helper));
            il.Add(Instruction.Create(DnOpCodes.Ret));
        }
    }
}
