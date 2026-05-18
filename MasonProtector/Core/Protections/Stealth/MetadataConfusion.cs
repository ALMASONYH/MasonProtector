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
    internal class MetadataConfusionProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal MetadataConfusionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyMetadataConfusion(ModuleDef module)
        {
            if (module.Assembly != null)
            {

                module.Assembly.Culture = "";
            }

            for (int i = 0; i < rng.Next(28, 60); i++)
            {
                var trapType = new TypeDefUser("", engine.MakeName(rng.Next(8, 24)),
                    module.CorLibTypes.Object.TypeDefOrRef);

                if (rng.Next(0, 3) == 0)
                {
                    trapType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Interface |
                        DnTypeAttributes.Abstract;
                }
                else
                {
                    trapType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                        DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                }

                for (int j = 0; j < rng.Next(5, 16); j++)
                {
                    TypeSig fieldType;
                    switch (rng.Next(0, 6))
                    {
                        case 0: fieldType = module.CorLibTypes.IntPtr; break;
                        case 1: fieldType = module.CorLibTypes.UIntPtr; break;
                        case 2: fieldType = new SZArraySig(module.CorLibTypes.Byte); break;
                        case 3: fieldType = module.CorLibTypes.Object; break;
                        case 4: fieldType = module.CorLibTypes.String; break;
                        default: fieldType = module.CorLibTypes.Int32; break;
                    }
                    trapType.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(6, 14)),
                        new FieldSig(fieldType),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 9); m++)
                {
                    var trapMethod = new MethodDefUser(engine.MakeName(rng.Next(6, 16)),
                        MethodSig.CreateStatic(module.CorLibTypes.Void),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                    trapMethod.Body = new CilBody();
                    trapMethod.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                    trapType.Methods.Add(trapMethod);
                    engine.injectedMethods.Add(trapMethod);
                }

                if (rng.Next(0, 3) == 0)
                {
                    var nested = new TypeDefUser("", engine.MakeName(rng.Next(6, 14)),
                        module.CorLibTypes.Object.TypeDefOrRef);
                    nested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                        DnTypeAttributes.Sealed;
                    nested.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.IntPtr),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                    trapType.NestedTypes.Add(nested);
                    engine.injectedTypes.Add(nested);
                }

                module.Types.Add(trapType);
                engine.injectedTypes.Add(trapType);
            }

            var modType = module.Types.FirstOrDefault(t => t.Name == "<Module>");
            if (modType != null)
            {
                for (int i = 0; i < rng.Next(32, 80); i++)
                {
                    TypeSig modFieldType;
                    switch (rng.Next(0, 4))
                    {
                        case 0: modFieldType = module.CorLibTypes.Int32; break;
                        case 1: modFieldType = module.CorLibTypes.IntPtr; break;
                        case 2: modFieldType = new SZArraySig(module.CorLibTypes.Byte); break;
                        default: modFieldType = module.CorLibTypes.Int64; break;
                    }
                    modType.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(6, 16)),
                        new FieldSig(modFieldType),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }
            }

            for (int i = 0; i < rng.Next(18, 40); i++)
            {
                byte[] fakeResData = engine.CryptoRandom(rng.Next(32, 512));
                module.Resources.Add(new EmbeddedResource(engine.MakeName(rng.Next(10, 20)), fakeResData));
            }
        }
    }
}

