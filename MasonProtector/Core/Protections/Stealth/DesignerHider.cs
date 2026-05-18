using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class DesignerHiderProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal DesignerHiderProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal int ApplyDesignerHider(ModuleDef module)
        {
            int processed = 0;
            foreach (TypeDef t in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(t)) continue;
                if (!engine.IsWinFormsType(t)) continue;

                if (engine.IsTypeUserExcluded(t)) continue;

                StripDesignerAttribute(t);

                foreach (MethodDef m in t.Methods)
                {
                    if (m == null) continue;
                    bool isIC = (m.Name == "InitializeComponent");
                    bool isDisp = (m.Name == "Dispose" && m.MethodSig != null &&
                                   m.MethodSig.Params.Count == 1 &&
                                   m.MethodSig.Params[0].FullName == "System.Boolean");
                    if (!isIC && !isDisp) continue;
                    if (engine.IsMethodUserExcluded(m)) continue;

                    StripDebuggerAttributes(m);

                    if (isIC)
                    {

                        processed++;
                    }

                }
            }
            return processed;
        }

        private void StripDesignerAttribute(TypeDef t)
        {
            if (!t.HasCustomAttributes) return;
            var attrs = t.CustomAttributes;
            for (int i = attrs.Count - 1; i >= 0; i--)
            {
                if (attrs[i].AttributeType == null) continue;
                string fn = attrs[i].AttributeType.FullName;
                if (fn == "Microsoft.VisualBasic.CompilerServices.DesignerGeneratedAttribute" ||
                    fn == "System.ComponentModel.DesignerCategoryAttribute")
                {
                    attrs.RemoveAt(i);
                }
            }
        }

        private void StripDebuggerAttributes(MethodDef m)
        {
            if (!m.HasCustomAttributes) return;
            var attrs = m.CustomAttributes;
            for (int i = attrs.Count - 1; i >= 0; i--)
            {
                if (attrs[i].AttributeType == null) continue;
                string fn = attrs[i].AttributeType.FullName;

                if (fn == "System.Diagnostics.DebuggerStepThroughAttribute" ||
                    fn == "System.Diagnostics.DebuggerNonUserCodeAttribute" ||
                    fn == "System.Diagnostics.DebuggerHiddenAttribute")
                {
                    attrs.RemoveAt(i);
                }
            }
        }
    }
}

