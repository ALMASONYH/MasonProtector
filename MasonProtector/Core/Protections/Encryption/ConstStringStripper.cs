using System;
using System.Collections.Generic;
using dnlib.DotNet;
using DnFieldAttributes = dnlib.DotNet.FieldAttributes;

namespace MasonProtector.Core
{
    internal class ConstStringStripperProtection
    {
        private Obfuscation engine;

        internal ConstStringStripperProtection(Obfuscation eng)
        {
            engine = eng;
        }

        internal int ApplyStripping(ModuleDef module)
        {
            int stripped = 0;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(type)) continue;

                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (FieldDef field in type.Fields)
                {
                    if (!field.IsLiteral) continue;
                    if (!field.IsStatic) continue;
                    if (field.Constant == null) continue;

                    if (field.FieldType == null) continue;
                    if (field.FieldType.FullName != "System.String") continue;
                    string val = field.Constant.Value as string;
                    if (val == null) continue;

                    if (val.Length == 0) continue;

                    field.Constant.Value = "";
                    stripped++;
                }
            }
            return stripped;
        }
    }
}

