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
    internal class AntiILDasmProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal AntiILDasmProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiILDasm(ModuleDef module, TypeDef modType)
        {
            InjectSuppressILDasmAttribute(module);
            InjectConfusingTypeStructures(module);
            InjectDeepNestedTypes(module);
            InjectMalformedAttributes(module);
            InjectTrapMethods(module, modType);
        }

        private void InjectSuppressILDasmAttribute(ModuleDef module)
        {
            var suppressType = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices",
                "SuppressIldasmAttribute");

            bool alreadyHas = false;
            if (module.Assembly != null)
            {
                foreach (var attr in module.Assembly.CustomAttributes)
                {
                    if (attr.TypeFullName != null &&
                        attr.TypeFullName.Contains("SuppressIldasm"))
                    {
                        alreadyHas = true;
                        break;
                    }
                }
            }

            if (!alreadyHas)
            {
                var attrType = new TypeDefUser("System.Runtime.CompilerServices",
                    "SuppressIldasmAttribute",
                    module.CorLibTypes.GetTypeRef("System", "Attribute"));
                attrType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed;
                module.Types.Add(attrType);
                engine.injectedTypes.Add(attrType);

                var ctor = new MethodDefUser(".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                    DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
                ctor.Body = new CilBody();
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));

                var baseCtor = new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    module.CorLibTypes.GetTypeRef("System", "Attribute"));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, baseCtor));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                attrType.Methods.Add(ctor);
                engine.injectedMethods.Add(ctor);

                if (module.Assembly != null)
                {
                    var ca = new CustomAttribute(ctor);
                    module.Assembly.CustomAttributes.Add(ca);
                }
            }
        }

        private void InjectConfusingTypeStructures(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(10, 22); i++)
            {
                var confusingType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                confusingType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(confusingType);
                engine.injectedTypes.Add(confusingType);

                for (int f = 0; f < rng.Next(3, 8); f++)
                {
                    var fieldType = GetRandomFieldType(module);
                    confusingType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(fieldType),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(2, 5); m++)
                {
                    var paramCount = rng.Next(0, 4);
                    var paramTypes = new TypeSig[paramCount];
                    for (int p = 0; p < paramCount; p++)
                        paramTypes[p] = GetRandomParamType(module);

                    var retType = rng.Next(0, 2) == 0 ? module.CorLibTypes.Void : module.CorLibTypes.Int32;

                    var fakeMethod = new MethodDefUser(engine.MakeName(),
                        MethodSig.CreateStatic(retType, paramTypes),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

                    fakeMethod.Body = new CilBody();
                    var il = fakeMethod.Body.Instructions;

                    for (int j = 0; j < rng.Next(3, 12); j++)
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Pop));
                    }

                    if (retType.FullName != "System.Void")
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    }
                    il.Add(Instruction.Create(DnOpCodes.Ret));

                    confusingType.Methods.Add(fakeMethod);
                    engine.injectedMethods.Add(fakeMethod);
                }
            }
        }

        private void InjectDeepNestedTypes(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(6, 14); i++)
            {
                var outerType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                outerType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(outerType);
                engine.injectedTypes.Add(outerType);

                TypeDef current = outerType;
                int depth = rng.Next(6, 12);
                for (int d = 0; d < depth; d++)
                {
                    var nested = new TypeDefUser("", engine.MakeName(),
                        module.CorLibTypes.Object.TypeDefOrRef);
                    nested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                        DnTypeAttributes.Sealed;
                    current.NestedTypes.Add(nested);
                    engine.injectedTypes.Add(nested);

                    for (int f = 0; f < rng.Next(1, 4); f++)
                    {
                        nested.Fields.Add(new FieldDefUser(engine.MakeName(),
                            new FieldSig(module.CorLibTypes.Int32),
                            DnFieldAttributes.Private | DnFieldAttributes.Static));
                    }

                    var nestedMethod = new MethodDefUser(engine.MakeName(),
                        MethodSig.CreateStatic(module.CorLibTypes.Int32),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                    nestedMethod.Body = new CilBody();
                    nestedMethod.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    nestedMethod.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                    nested.Methods.Add(nestedMethod);
                    engine.injectedMethods.Add(nestedMethod);

                    current = nested;
                }
            }
        }

        private void InjectMalformedAttributes(ModuleDef module)
        {
            string[] fakeAttrNames = new string[]
            {
                "ObfuscatedByAttribute", "ProtectedAttribute", "NoDecompileAttribute",
                "SecuredAttribute", "LicensedAttribute", "EncryptedAttribute",
                "TamperProofAttribute", "ChecksumAttribute", "SignedAttribute"
            };

            int attrCount = rng.Next(10, 22);
            for (int i = 0; i < attrCount; i++)
            {
                string attrName = fakeAttrNames[rng.Next(0, fakeAttrNames.Length)];
                string ns = "System.Security." + engine.MakeName(6);

                var attrType = new TypeDefUser(ns, attrName,
                    module.CorLibTypes.GetTypeRef("System", "Attribute"));
                attrType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed;
                module.Types.Add(attrType);
                engine.injectedTypes.Add(attrType);

                var ctor = new MethodDefUser(".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                    DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
                ctor.Body = new CilBody();
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                var baseCtor = new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    module.CorLibTypes.GetTypeRef("System", "Attribute"));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, baseCtor));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                attrType.Methods.Add(ctor);
                engine.injectedMethods.Add(ctor);

                for (int f = 0; f < rng.Next(1, 4); f++)
                {
                    attrType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.String),
                        DnFieldAttributes.Private));
                }

                if (module.Assembly != null)
                {
                    var ca = new CustomAttribute(ctor);
                    module.Assembly.CustomAttributes.Add(ca);
                }
            }
        }

        private void InjectTrapMethods(ModuleDef module, TypeDef modType)
        {
            for (int i = 0; i < rng.Next(12, 26); i++)
            {
                var trapMethod = new MethodDefUser(engine.MakeName(),
                    MethodSig.CreateStatic(module.CorLibTypes.Int32),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

                trapMethod.Body = new CilBody();
                trapMethod.Body.InitLocals = true;
                trapMethod.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
                trapMethod.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
                var il = trapMethod.Body.Instructions;

                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));

                for (int j = 0; j < rng.Next(5, 15); j++)
                {
                    int op = rng.Next(0, 6);
                    switch (op)
                    {
                        case 0:
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                            il.Add(Instruction.Create(DnOpCodes.Xor));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                            break;
                        case 1:
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Not));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                            break;
                        case 2:
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                            il.Add(Instruction.Create(DnOpCodes.Shl));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                            break;
                        case 3:
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                            il.Add(Instruction.Create(DnOpCodes.Add));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                            break;
                        case 4:
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                            il.Add(Instruction.Create(DnOpCodes.And));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                            break;
                        default:
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                            il.Add(Instruction.Create(DnOpCodes.Or));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                            break;
                    }
                }

                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ret));

                modType.Methods.Add(trapMethod);
                engine.injectedMethods.Add(trapMethod);
            }
        }

        private TypeSig GetRandomFieldType(ModuleDef module)
        {
            int t = rng.Next(0, 6);
            switch (t)
            {
                case 0: return module.CorLibTypes.Int32;
                case 1: return module.CorLibTypes.Int64;
                case 2: return module.CorLibTypes.String;
                case 3: return module.CorLibTypes.Boolean;
                case 4: return new SZArraySig(module.CorLibTypes.Byte);
                default: return module.CorLibTypes.Object;
            }
        }

        private TypeSig GetRandomParamType(ModuleDef module)
        {
            int t = rng.Next(0, 4);
            switch (t)
            {
                case 0: return module.CorLibTypes.Int32;
                case 1: return module.CorLibTypes.String;
                case 2: return module.CorLibTypes.Boolean;
                default: return module.CorLibTypes.Object;
            }
        }
    }
}

