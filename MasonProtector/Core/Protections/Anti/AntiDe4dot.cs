using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class AntiDe4dotProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal AntiDe4dotProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiDe4dot(ModuleDef module, TypeDef modType)
        {
            for (int i = 0; i < rng.Next(18, 38); i++)
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

                for (int f = 0; f < rng.Next(2, 8); f++)
                {
                    TypeSig fType;
                    switch (rng.Next(0, 5))
                    {
                        case 0: fType = module.CorLibTypes.IntPtr; break;
                        case 1: fType = module.CorLibTypes.UIntPtr; break;
                        case 2: fType = new SZArraySig(module.CorLibTypes.Byte); break;
                        case 3: fType = module.CorLibTypes.Object; break;
                        default: fType = module.CorLibTypes.Int32; break;
                    }

                    trapType.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(4, 16)),
                        new FieldSig(fType),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(1, 4); m++)
                {
                    var trapMethod = new MethodDefUser(engine.MakeName(rng.Next(6, 16)),
                        MethodSig.CreateStatic(module.CorLibTypes.Void),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                    trapMethod.Body = new CilBody();
                    trapMethod.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                    trapType.Methods.Add(trapMethod);
                    engine.injectedMethods.Add(trapMethod);
                }

                if (rng.Next(0, 3) == 0)
                {
                    var iface = new TypeDefUser("", engine.MakeName(rng.Next(8, 20)),
                        null);
                    iface.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Interface | DnTypeAttributes.Abstract;
                    module.Types.Add(iface);
                    engine.injectedTypes.Add(iface);

                    var ifaceImpl = new InterfaceImplUser(iface);
                    trapType.Interfaces.Add(ifaceImpl);
                }

                module.Types.Add(trapType);
                engine.injectedTypes.Add(trapType);
            }

            for (int i = 0; i < rng.Next(10, 22); i++)
            {
                var loopType = new TypeDefUser("", engine.MakeName(rng.Next(8, 20)),
                    module.CorLibTypes.Object.TypeDefOrRef);
                loopType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;

                var nested = new TypeDefUser("", engine.MakeName(rng.Next(6, 14)),
                    module.CorLibTypes.Object.TypeDefOrRef);
                nested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                loopType.NestedTypes.Add(nested);

                nested.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.IntPtr),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));

                module.Types.Add(loopType);
                engine.injectedTypes.Add(loopType);
                engine.injectedTypes.Add(nested);
            }

        }
    }
}

