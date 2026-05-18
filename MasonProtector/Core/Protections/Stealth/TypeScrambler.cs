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
    internal class TypeScramblerProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int ABSTRACT_TYPE_COUNT = 16;
        private const int INTERFACE_COUNT = 14;
        private const int SEALED_TYPE_COUNT = 14;
        private const int GENERIC_TYPE_COUNT = 10;
        private const int NESTED_DEPTH_MAX = 9;
        private const int CIRCULAR_PAIR_COUNT = 10;
        private const int ENUM_COUNT = 14;
        private const int EVENT_TYPE_COUNT = 10;
        private const int DELEGATE_TYPE_COUNT = 10;
        private const int OVERLOAD_SET_COUNT = 14;

        internal TypeScramblerProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyTypeScrambler(ModuleDef module, TypeDef modType)
        {
            InjectFakeAbstractTypes(module);
            InjectFakeInterfaces(module);
            InjectSealedTypes(module);
            InjectGenericTypes(module);
            InjectDeepNestedHierarchy(module);
            InjectCircularFieldReferences(module);
            InjectOverloadedMethodSets(module);
            InjectPhantomEnums(module);
            InjectDummyEvents(module);
            InjectProxyDelegateTypes(module);
            InjectModuleTypeFields(module, modType);
        }

        private void InjectFakeAbstractTypes(ModuleDef module)
        {
            for (int i = 0; i < ABSTRACT_TYPE_COUNT; i++)
            {
                var absType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                absType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.BeforeFieldInit;

                int fieldCount = rng.Next(5, 12);
                for (int f = 0; f < fieldCount; f++)
                {
                    TypeSig ft = PickFieldType(module);
                    DnFieldAttributes fa;
                    int pick = rng.Next(0, 3);
                    if (pick == 0) fa = DnFieldAttributes.Family;
                    else if (pick == 1) fa = DnFieldAttributes.Private;
                    else fa = DnFieldAttributes.Assembly;

                    absType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft), fa));
                }

                for (int m = 0; m < rng.Next(3, 7); m++)
                {
                    if (rng.Next(0, 3) == 0)
                    {
                        var absMeth = BuildAbstractMethod(module);
                        absType.Methods.Add(absMeth);
                        engine.injectedMethods.Add(absMeth);
                    }
                    else
                    {
                        var concMeth = BuildComputeMethod(module);
                        absType.Methods.Add(concMeth);
                        engine.injectedMethods.Add(concMeth);
                    }
                }

                var ctor = BuildInstanceCtor(module);
                absType.Methods.Add(ctor);
                engine.injectedMethods.Add(ctor);

                module.Types.Add(absType);
                engine.injectedTypes.Add(absType);
            }
        }

        private void InjectFakeInterfaces(ModuleDef module)
        {
            for (int i = 0; i < INTERFACE_COUNT; i++)
            {
                var iface = new TypeDefUser("", engine.MakeName(), null);
                iface.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Interface |
                    DnTypeAttributes.Abstract;

                int methodCount = rng.Next(3, 7);
                for (int m = 0; m < methodCount; m++)
                {
                    int paramCount = rng.Next(0, 5);
                    var paramTypes = new List<TypeSig>();
                    for (int p = 0; p < paramCount; p++)
                    {
                        int t = rng.Next(0, 5);
                        if (t == 0) paramTypes.Add(module.CorLibTypes.Int32);
                        else if (t == 1) paramTypes.Add(module.CorLibTypes.String);
                        else if (t == 2) paramTypes.Add(module.CorLibTypes.Boolean);
                        else if (t == 3) paramTypes.Add(module.CorLibTypes.Int64);
                        else paramTypes.Add(module.CorLibTypes.Object);
                    }

                    TypeSig retType;
                    int r = rng.Next(0, 6);
                    if (r == 0) retType = module.CorLibTypes.Void;
                    else if (r == 1) retType = module.CorLibTypes.Int32;
                    else if (r == 2) retType = module.CorLibTypes.String;
                    else if (r == 3) retType = module.CorLibTypes.Boolean;
                    else if (r == 4) retType = module.CorLibTypes.Double;
                    else retType = module.CorLibTypes.Object;

                    var sig = MethodSig.CreateInstance(retType, paramTypes.ToArray());
                    var method = new MethodDefUser(engine.MakeName(), sig,
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Public | DnMethodAttributes.Virtual |
                        DnMethodAttributes.HideBySig | DnMethodAttributes.NewSlot |
                        DnMethodAttributes.Abstract);
                    iface.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }

                module.Types.Add(iface);
                engine.injectedTypes.Add(iface);
            }
        }

        private void InjectSealedTypes(ModuleDef module)
        {
            for (int i = 0; i < SEALED_TYPE_COUNT; i++)
            {
                var sealedType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                sealedType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed |
                    DnTypeAttributes.BeforeFieldInit;

                int fieldCount = rng.Next(6, 14);
                for (int f = 0; f < fieldCount; f++)
                {
                    TypeSig ft = PickFieldType(module);
                    DnFieldAttributes fa;
                    int pick = rng.Next(0, 3);
                    if (pick == 0) fa = DnFieldAttributes.Private;
                    else if (pick == 1) fa = DnFieldAttributes.Private | DnFieldAttributes.Static;
                    else fa = DnFieldAttributes.Private | DnFieldAttributes.InitOnly;

                    sealedType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft), fa));
                }

                for (int m = 0; m < rng.Next(4, 8); m++)
                {
                    var method = BuildComputeMethod(module);
                    sealedType.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }

                var ctor = BuildInstanceCtor(module);
                sealedType.Methods.Add(ctor);
                engine.injectedMethods.Add(ctor);

                var trapMeth = BuildTryCatchMethod(module);
                sealedType.Methods.Add(trapMeth);
                engine.injectedMethods.Add(trapMeth);

                module.Types.Add(sealedType);
                engine.injectedTypes.Add(sealedType);
            }
        }

        private void InjectGenericTypes(ModuleDef module)
        {
            for (int g = 0; g < GENERIC_TYPE_COUNT; g++)
            {
                var genType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                genType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.BeforeFieldInit;

                int genParamCount = rng.Next(1, 5);
                for (int p = 0; p < genParamCount; p++)
                {
                    var gp = new GenericParamUser((ushort)p, GenericParamAttributes.NonVariant,
                        engine.MakeName());
                    genType.GenericParameters.Add(gp);
                }

                int fieldCount = rng.Next(4, 10);
                for (int f = 0; f < fieldCount; f++)
                {
                    TypeSig ft;
                    int t = rng.Next(0, 7);
                    if (t == 0) ft = module.CorLibTypes.Int32;
                    else if (t == 1) ft = module.CorLibTypes.Int64;
                    else if (t == 2) ft = module.CorLibTypes.Boolean;
                    else if (t == 3) ft = module.CorLibTypes.Byte;
                    else if (t == 4) ft = module.CorLibTypes.Double;
                    else if (t == 5) ft = new SZArraySig(module.CorLibTypes.Int32);
                    else ft = new SZArraySig(module.CorLibTypes.Byte);

                    genType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 6); m++)
                {
                    var method = BuildComputeMethod(module);
                    genType.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }

                module.Types.Add(genType);
                engine.injectedTypes.Add(genType);
            }
        }

        private void InjectDeepNestedHierarchy(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(2, 5); i++)
            {
                var rootType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                rootType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

                for (int f = 0; f < rng.Next(3, 7); f++)
                {
                    rootType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(PickFieldType(module)),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(2, 5); m++)
                {
                    var method = BuildComputeMethod(module);
                    rootType.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }

                module.Types.Add(rootType);
                engine.injectedTypes.Add(rootType);

                TypeDef current = rootType;
                int depth = rng.Next(3, NESTED_DEPTH_MAX + 1);
                for (int d = 0; d < depth; d++)
                {
                    var nested = new TypeDefUser("", engine.MakeName(),
                        module.CorLibTypes.Object.TypeDefOrRef);
                    nested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                        DnTypeAttributes.Sealed;

                    for (int f = 0; f < rng.Next(2, 6); f++)
                    {
                        nested.Fields.Add(new FieldDefUser(engine.MakeName(),
                            new FieldSig(PickFieldType(module)),
                            DnFieldAttributes.Private | DnFieldAttributes.Static));
                    }

                    for (int m = 0; m < rng.Next(2, 4); m++)
                    {
                        var method = BuildComputeMethod(module);
                        nested.Methods.Add(method);
                        engine.injectedMethods.Add(method);
                    }

                    current.NestedTypes.Add(nested);
                    engine.injectedTypes.Add(nested);
                    current = nested;
                }
            }
        }

        private void InjectCircularFieldReferences(ModuleDef module)
        {
            for (int i = 0; i < CIRCULAR_PAIR_COUNT; i++)
            {
                var typeA = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                typeA.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

                var typeB = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                typeB.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

                module.Types.Add(typeA);
                module.Types.Add(typeB);

                typeA.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(new ClassSig(typeB)),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
                typeA.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(new ClassSig(typeB))),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));

                typeB.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(new ClassSig(typeA)),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
                typeB.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(new ClassSig(typeA))),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));

                for (int f = 0; f < rng.Next(3, 7); f++)
                {
                    typeA.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(PickFieldType(module)),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                    typeB.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(PickFieldType(module)),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 6); m++)
                {
                    var methA = BuildComputeMethod(module);
                    typeA.Methods.Add(methA);
                    engine.injectedMethods.Add(methA);

                    var methB = BuildTryCatchMethod(module);
                    typeB.Methods.Add(methB);
                    engine.injectedMethods.Add(methB);
                }

                engine.injectedTypes.Add(typeA);
                engine.injectedTypes.Add(typeB);
            }
        }

        private void InjectOverloadedMethodSets(ModuleDef module)
        {
            var hostTypes = module.Types.Where(t => engine.injectedTypes.Contains(t) &&
                !t.IsInterface).ToList();

            for (int s = 0; s < OVERLOAD_SET_COUNT; s++)
            {
                if (hostTypes.Count == 0) break;
                var host = hostTypes[rng.Next(hostTypes.Count)];
                string baseName = engine.MakeName();

                for (int o = 0; o < rng.Next(3, 7); o++)
                {
                    int paramCount = o + 1;
                    var paramTypes = new List<TypeSig>();
                    for (int p = 0; p < paramCount; p++)
                    {
                        int t = rng.Next(0, 4);
                        if (t == 0) paramTypes.Add(module.CorLibTypes.Int32);
                        else if (t == 1) paramTypes.Add(module.CorLibTypes.Int64);
                        else if (t == 2) paramTypes.Add(module.CorLibTypes.Boolean);
                        else paramTypes.Add(module.CorLibTypes.Byte);
                    }

                    TypeSig retType;
                    int r = rng.Next(0, 3);
                    if (r == 0) retType = module.CorLibTypes.Int32;
                    else if (r == 1) retType = module.CorLibTypes.Int64;
                    else retType = module.CorLibTypes.Boolean;

                    var method = new MethodDefUser(baseName,
                        MethodSig.CreateStatic(retType, paramTypes.ToArray()),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

                    method.Body = new CilBody();
                    method.Body.InitLocals = true;
                    method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
                    method.Body.Variables.Add(new Local(module.CorLibTypes.Int64));
                    var il = method.Body.Instructions;

                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));

                    for (int k = 0; k < rng.Next(4, 9); k++)
                    {
                        int op = rng.Next(0, 4);
                        if (op == 0)
                        {
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                            il.Add(Instruction.Create(DnOpCodes.Xor));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        }
                        else if (op == 1)
                        {
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                            il.Add(Instruction.Create(DnOpCodes.Add));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        }
                        else if (op == 2)
                        {
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                            il.Add(Instruction.Create(DnOpCodes.Sub));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        }
                        else
                        {
                            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
                            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        }
                    }

                    if (retType.FullName == "System.Int32")
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ret));
                    }
                    else if (retType.FullName == "System.Int64")
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ret));
                    }
                    else
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                        il.Add(Instruction.Create(DnOpCodes.Ceq));
                        il.Add(Instruction.Create(DnOpCodes.Ret));
                    }

                    host.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }
            }
        }

        private void InjectPhantomEnums(ModuleDef module)
        {
            var enumBaseRef = module.CorLibTypes.GetTypeRef("System", "Enum");

            for (int i = 0; i < ENUM_COUNT; i++)
            {
                var enumType = new TypeDefUser("", engine.MakeName(), enumBaseRef);
                enumType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed;

                enumType.Fields.Add(new FieldDefUser("value__",
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Public | DnFieldAttributes.SpecialName |
                    DnFieldAttributes.RTSpecialName));

                int memberCount = rng.Next(4, 12);
                for (int m = 0; m < memberCount; m++)
                {
                    var enumField = new FieldDefUser(engine.MakeName(),
                        new FieldSig(new ValueTypeSig(enumType)),
                        DnFieldAttributes.Public | DnFieldAttributes.Static |
                        DnFieldAttributes.Literal | DnFieldAttributes.HasDefault);
                    enumField.Constant = new ConstantUser(m, dnlib.DotNet.ElementType.I4);
                    enumType.Fields.Add(enumField);
                }

                module.Types.Add(enumType);
                engine.injectedTypes.Add(enumType);
            }
        }

        private void InjectDummyEvents(ModuleDef module)
        {
            var hostTypes = module.Types.Where(t => engine.injectedTypes.Contains(t) &&
                !t.IsInterface && !t.IsEnum &&
                !(t.IsAbstract && t.IsSealed)).ToList();

            for (int i = 0; i < EVENT_TYPE_COUNT; i++)
            {
                if (hostTypes.Count == 0) break;
                var host = hostTypes[rng.Next(hostTypes.Count)];

                var eventHandlerRef = module.CorLibTypes.GetTypeRef("System", "EventHandler");
                var eventHandlerSig = new ClassSig(eventHandlerRef);

                string evtName = engine.MakeName();

                var backingField = new FieldDefUser(engine.MakeName(),
                    new FieldSig(eventHandlerSig),
                    DnFieldAttributes.Private | DnFieldAttributes.Static);
                host.Fields.Add(backingField);

                var addMethod = new MethodDefUser("add_" + evtName,
                    MethodSig.CreateStatic(module.CorLibTypes.Void, eventHandlerSig),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName);
                addMethod.Body = new CilBody();
                addMethod.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                host.Methods.Add(addMethod);
                engine.injectedMethods.Add(addMethod);

                var removeMethod = new MethodDefUser("remove_" + evtName,
                    MethodSig.CreateStatic(module.CorLibTypes.Void, eventHandlerSig),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName);
                removeMethod.Body = new CilBody();
                removeMethod.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                host.Methods.Add(removeMethod);
                engine.injectedMethods.Add(removeMethod);

                var evt = new EventDefUser(evtName, eventHandlerRef);
                evt.AddMethod = addMethod;
                evt.RemoveMethod = removeMethod;
                host.Events.Add(evt);
            }
        }

        private void InjectProxyDelegateTypes(ModuleDef module)
        {
            var multicastRef = module.CorLibTypes.GetTypeRef("System", "MulticastDelegate");

            for (int i = 0; i < DELEGATE_TYPE_COUNT; i++)
            {
                var delType = new TypeDefUser("", engine.MakeName(), multicastRef);
                delType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed;

                int paramCount = rng.Next(1, 5);
                var paramTypes = new List<TypeSig>();
                for (int p = 0; p < paramCount; p++)
                {
                    int t = rng.Next(0, 5);
                    if (t == 0) paramTypes.Add(module.CorLibTypes.Int32);
                    else if (t == 1) paramTypes.Add(module.CorLibTypes.String);
                    else if (t == 2) paramTypes.Add(module.CorLibTypes.Boolean);
                    else if (t == 3) paramTypes.Add(module.CorLibTypes.Int64);
                    else paramTypes.Add(module.CorLibTypes.Object);
                }

                TypeSig retSig;
                int rv = rng.Next(0, 4);
                if (rv == 0) retSig = module.CorLibTypes.Void;
                else if (rv == 1) retSig = module.CorLibTypes.Int32;
                else if (rv == 2) retSig = module.CorLibTypes.Boolean;
                else retSig = module.CorLibTypes.String;

                var delCtor = new MethodDefUser(".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void,
                        module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                    DnMethodImplAttributes.Runtime | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                    DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
                delType.Methods.Add(delCtor);
                engine.injectedMethods.Add(delCtor);

                var invokeMethod = new MethodDefUser("Invoke",
                    MethodSig.CreateInstance(retSig, paramTypes.ToArray()),
                    DnMethodImplAttributes.Runtime | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.Virtual |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.NewSlot);
                delType.Methods.Add(invokeMethod);
                engine.injectedMethods.Add(invokeMethod);

                var beginInvoke = new MethodDefUser("BeginInvoke",
                    MethodSig.CreateInstance(module.CorLibTypes.Object, paramTypes.ToArray()),
                    DnMethodImplAttributes.Runtime | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.Virtual |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.NewSlot);
                delType.Methods.Add(beginInvoke);
                engine.injectedMethods.Add(beginInvoke);

                var endInvoke = new MethodDefUser("EndInvoke",
                    MethodSig.CreateInstance(retSig, module.CorLibTypes.Object),
                    DnMethodImplAttributes.Runtime | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.Virtual |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.NewSlot);
                delType.Methods.Add(endInvoke);
                engine.injectedMethods.Add(endInvoke);

                for (int f = 0; f < rng.Next(2, 5); f++)
                {
                    delType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(PickFieldType(module)),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                module.Types.Add(delType);
                engine.injectedTypes.Add(delType);
            }
        }

        private void InjectModuleTypeFields(ModuleDef module, TypeDef modType)
        {
            if (modType == null) return;

            for (int i = 0; i < rng.Next(8, 18); i++)
            {
                TypeSig ft = PickFieldType(module);
                modType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }

            for (int i = 0; i < rng.Next(3, 6); i++)
            {
                var method = BuildTryCatchMethod(module);
                modType.Methods.Add(method);
                engine.injectedMethods.Add(method);
            }
        }

        private TypeSig PickFieldType(ModuleDef module)
        {
            int t = rng.Next(0, 8);
            if (t == 0) return module.CorLibTypes.Int32;
            if (t == 1) return module.CorLibTypes.Int64;
            if (t == 2) return module.CorLibTypes.Boolean;
            if (t == 3) return module.CorLibTypes.Byte;
            if (t == 4) return module.CorLibTypes.Double;
            if (t == 5) return new SZArraySig(module.CorLibTypes.Int32);
            if (t == 6) return new SZArraySig(module.CorLibTypes.Byte);
            return module.CorLibTypes.String;
        }

        private MethodDef BuildAbstractMethod(ModuleDef module)
        {
            int paramCount = rng.Next(0, 4);
            var paramTypes = new List<TypeSig>();
            for (int p = 0; p < paramCount; p++)
            {
                int t = rng.Next(0, 4);
                if (t == 0) paramTypes.Add(module.CorLibTypes.Int32);
                else if (t == 1) paramTypes.Add(module.CorLibTypes.String);
                else if (t == 2) paramTypes.Add(module.CorLibTypes.Boolean);
                else paramTypes.Add(module.CorLibTypes.Object);
            }

            TypeSig retType;
            int r = rng.Next(0, 4);
            if (r == 0) retType = module.CorLibTypes.Void;
            else if (r == 1) retType = module.CorLibTypes.Int32;
            else if (r == 2) retType = module.CorLibTypes.Boolean;
            else retType = module.CorLibTypes.String;

            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateInstance(retType, paramTypes.ToArray()),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Family | DnMethodAttributes.Virtual |
                DnMethodAttributes.HideBySig | DnMethodAttributes.NewSlot |
                DnMethodAttributes.Abstract);
            return method;
        }

        private MethodDef BuildInstanceCtor(ModuleDef module)
        {
            var ctor = new MethodDefUser(".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Family | DnMethodAttributes.HideBySig |
                DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
            ctor.Body = new CilBody();

            var baseCtorRef = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                module.CorLibTypes.Object.TypeDefOrRef);
            ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, baseCtorRef));
            ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            return ctor;
        }

        private MethodDef BuildComputeMethod(ModuleDef module)
        {
            int paramCount = rng.Next(1, 4);
            var paramTypes = new List<TypeSig>();
            for (int p = 0; p < paramCount; p++)
                paramTypes.Add(module.CorLibTypes.Int32);

            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, paramTypes.ToArray()),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            int rounds = rng.Next(6, 14);
            for (int r = 0; r < rounds; r++)
            {
                int op = rng.Next(0, 7);
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
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Or));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    case 4:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 5:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.And));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildTryCatchMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Ldc_I4, rng.Next());
            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            var afterHandler = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int n = 0; n < rng.Next(4, 10); n++)
            {
                int op = rng.Next(0, 5);
                if (op == 0)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                }
                else if (op == 1)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                }
                else if (op == 2)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                    il.Add(Instruction.Create(DnOpCodes.Shl));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                }
                else if (op == 3)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                }
                else
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Leave, afterHandler));

            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterHandler));

            il.Add(afterHandler);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            var exHandler = new ExceptionHandler(ExceptionHandlerType.Catch);
            exHandler.TryStart = tryStart;
            exHandler.TryEnd = handlerStart;
            exHandler.HandlerStart = handlerStart;
            exHandler.HandlerEnd = afterHandler;
            exHandler.CatchType = module.CorLibTypes.GetTypeRef("System", "Exception");
            method.Body.ExceptionHandlers.Add(exHandler);

            return method;
        }
    }
}

