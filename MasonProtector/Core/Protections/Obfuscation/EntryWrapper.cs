using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class EntryWrapperProtection
    {
        private Obfuscation engine;

        internal EntryWrapperProtection(Obfuscation eng)
        {
            engine = eng;
        }

        internal int ApplyEntryWrappers(ModuleDef module)
        {

            MethodDef entry = module.EntryPoint;
            if (entry == null || entry.DeclaringType == null) return 0;
            TypeDef entryType = entry.DeclaringType;

            TypeDef modType = module.GlobalType;
            if (modType == null) return 0;
            MethodDef cctor = modType.FindStaticConstructor();
            if (cctor == null || cctor.Body == null) return 0;

            var instructions = cctor.Body.Instructions;
            var sites = new List<int>();
            for (int i = 0; i < instructions.Count; i++)
            {
                var ins = instructions[i];
                if (ins.OpCode.Code != Code.Call) continue;
                MethodDef target = ins.Operand as MethodDef;
                if (target == null) continue;
                if (!target.IsStatic) continue;
                if (target.HasGenericParameters) continue;
                if (target.MethodSig == null) continue;

                if (target.MethodSig.Params.Count != 0) continue;
                if (target.MethodSig.RetType == null ||
                    target.MethodSig.RetType.FullName != "System.Void") continue;

                if (target.DeclaringType == entryType) continue;
                if (target.DeclaringType == modType) continue;

                if (engine.injectedMethods.Contains(target)) continue;
                sites.Add(i);
            }
            if (sites.Count == 0) return 0;

            int maxWrappers = Math.Min(sites.Count, 4);
            int wrapped = 0;

            int entryIdx = entryType.Methods.IndexOf(entry);
            int insertAt = entryIdx >= 0 ? entryIdx + 1 : entryType.Methods.Count;

            for (int s = 0; s < maxWrappers; s++)
            {
                int siteIdx = sites[s];
                Instruction site = instructions[siteIdx];
                MethodDef target = (MethodDef)site.Operand;

                MethodDef wrapper = new MethodDefUser(
                    engine.MakeName(),
                    MethodSig.CreateStatic(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig);
                wrapper.Body = new CilBody();
                wrapper.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, target));
                wrapper.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));

                entryType.Methods.Insert(insertAt, wrapper);
                insertAt++;
                engine.injectedMethods.Add(wrapper);

                site.Operand = wrapper;

                try { target.Name = engine.MakeName(); } catch { }

                wrapped++;
            }
            return wrapped;
        }
    }
}

