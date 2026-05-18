using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class FakeAttributesProtection
    {
        private Obfuscation engine;
        private Random rng;

        private static readonly string[] confuserMarkers = new string[]
        {
            "ConfusedByAttribute", "Confuser.Core", "ConfuserEx",
            "Dotfuscator.Attributes", "SmartAssembly.Attributes",
            "BabelObfuscatorAttribute", "EazObfuscator", "Xenocode.Client",
            "ReactorAttribute", "CryptoObfuscator", "Agile.NET",
            "MaxtoCode", "Goliath.NET", "Spices.NET", "Skater.NET"
        };

        internal FakeAttributesProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyFakeAttributes(ModuleDef module)
        {
            foreach (string marker in confuserMarkers)
            {
                if (rng.Next(0, 6) == 0) continue;

                var fakeType = new TypeDefUser("", marker + "Attribute",
                    module.Import(typeof(Attribute)));
                fakeType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed;

                var ctor = new MethodDefUser(".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                    DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
                ctor.Body = new CilBody();
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                var attrCtor = module.Import(typeof(Attribute).GetConstructor(
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
                    null, Type.EmptyTypes, null));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, attrCtor));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                fakeType.Methods.Add(ctor);

                for (int f = 0; f < rng.Next(4, 10); f++)
                {
                    fakeType.Fields.Add(new FieldDefUser(engine.MakeName(8),
                        new FieldSig(module.CorLibTypes.String),
                        DnFieldAttributes.Private));
                }

                module.Types.Add(fakeType);
                engine.injectedTypes.Add(fakeType);

                if (module.Assembly != null)
                {
                    module.Assembly.CustomAttributes.Add(new CustomAttribute(ctor));
                }
            }

            var suppressAttr = new TypeDefUser("System.Runtime.CompilerServices", "SuppressIldasmAttribute",
                module.Import(typeof(Attribute)));
            suppressAttr.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed;

            var suppressCtor = new MethodDefUser(".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
            suppressCtor.Body = new CilBody();
            suppressCtor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            var baseAttrCtor = module.Import(typeof(Attribute).GetConstructor(
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
                null, Type.EmptyTypes, null));
            suppressCtor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, baseAttrCtor));
            suppressCtor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            suppressAttr.Methods.Add(suppressCtor);
            module.Types.Add(suppressAttr);
            engine.injectedTypes.Add(suppressAttr);

            if (module.Assembly != null)
                module.Assembly.CustomAttributes.Add(new CustomAttribute(suppressCtor));
        }
    }
}

