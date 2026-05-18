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
    internal class InvalidMetadataProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int PHANTOM_TYPE_COUNT = 28;
        private const int PHANTOM_NESTING_DEPTH = 10;
        private const int PHANTOM_METHOD_COUNT = 36;
        private const int PHANTOM_FIELD_COUNT = 48;
        private const int GHOST_INTERFACE_COUNT = 22;
        private const int CONFUSION_ATTRIBUTE_COUNT = 28;
        private const int DECOY_RESOURCE_COUNT = 14;
        private const int TRAP_METHOD_COUNT = 26;
        private const int OVERLOAD_COUNT = 18;
        private const int DUMMY_GENERIC_COUNT = 14;

        internal InvalidMetadataProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyInvalidMetadata(ModuleDef module, TypeDef modType)
        {
            InjectPhantomTypes(module);
            InjectDeepNestedTypes(module);
            InjectGhostInterfaces(module);
            InjectConfusionAttributes(module);
            InjectPhantomMethods(module);
            InjectPhantomFields(module);
            InjectTrapMethods(module);
            InjectOverloadedMethods(module);
            InjectDummyGenerics(module);
            InjectMalformedNames(module);
            InjectCircularReferences(module);
            InjectDecoyResources(module);
            InjectPInvokeDecoys(module);
            InjectModuleAttributes(module);
        }

        private void InjectPhantomTypes(ModuleDef module)
        {
            for (int i = 0; i < PHANTOM_TYPE_COUNT; i++)
            {
                var phantom = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);

                DnTypeAttributes attrs;
                int pick = rng.Next(0, 4);
                if (pick == 0) attrs = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract | DnTypeAttributes.Sealed;
                else if (pick == 1) attrs = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract;
                else if (pick == 2) attrs = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed;
                else attrs = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

                phantom.Attributes = attrs;
                module.Types.Add(phantom);
                engine.injectedTypes.Add(phantom);

                for (int f = 0; f < rng.Next(4, 10); f++)
                {
                    TypeSig ft;
                    int t = rng.Next(0, 6);
                    if (t == 0) ft = module.CorLibTypes.Int32;
                    else if (t == 1) ft = module.CorLibTypes.Int64;
                    else if (t == 2) ft = module.CorLibTypes.Boolean;
                    else if (t == 3) ft = module.CorLibTypes.Byte;
                    else if (t == 4) ft = module.CorLibTypes.Double;
                    else ft = module.CorLibTypes.String;

                    phantom.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 8); m++)
                {
                    var method = BuildPhantomComputeMethod(module);
                    phantom.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }
            }
        }

        private void InjectDeepNestedTypes(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(3, 6); i++)
            {
                var rootType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                rootType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(rootType);
                engine.injectedTypes.Add(rootType);

                TypeDef current = rootType;
                int depth = rng.Next(3, PHANTOM_NESTING_DEPTH + 1);
                for (int d = 0; d < depth; d++)
                {
                    var nested = new TypeDefUser("", engine.MakeName(),
                        module.CorLibTypes.Object.TypeDefOrRef);
                    nested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                        DnTypeAttributes.Sealed;
                    current.NestedTypes.Add(nested);
                    engine.injectedTypes.Add(nested);

                    for (int f = 0; f < rng.Next(2, 6); f++)
                    {
                        nested.Fields.Add(new FieldDefUser(engine.MakeName(),
                            new FieldSig(module.CorLibTypes.Int32),
                            DnFieldAttributes.Private | DnFieldAttributes.Static));
                    }

                    for (int m = 0; m < rng.Next(2, 5); m++)
                    {
                        var method = BuildPhantomComputeMethod(module);
                        nested.Methods.Add(method);
                        engine.injectedMethods.Add(method);
                    }

                    current = nested;
                }
            }
        }

        private void InjectGhostInterfaces(ModuleDef module)
        {
            for (int i = 0; i < GHOST_INTERFACE_COUNT; i++)
            {
                var iface = new TypeDefUser("", engine.MakeName(),
                    null);
                iface.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Interface |
                    DnTypeAttributes.Abstract;
                module.Types.Add(iface);
                engine.injectedTypes.Add(iface);

                for (int m = 0; m < rng.Next(2, 5); m++)
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
                    int r = rng.Next(0, 5);
                    if (r == 0) retType = module.CorLibTypes.Void;
                    else if (r == 1) retType = module.CorLibTypes.Int32;
                    else if (r == 2) retType = module.CorLibTypes.String;
                    else if (r == 3) retType = module.CorLibTypes.Boolean;
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
            }
        }

        private void InjectConfusionAttributes(ModuleDef module)
        {
            for (int i = 0; i < CONFUSION_ATTRIBUTE_COUNT; i++)
            {
                var attrType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.GetTypeRef("System", "Attribute"));
                attrType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed |
                    DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(attrType);
                engine.injectedTypes.Add(attrType);

                var ctor = new MethodDefUser(".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                    DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
                ctor.Body = new CilBody();
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));

                var baseCtorRef = new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    module.CorLibTypes.GetTypeRef("System", "Attribute"));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, baseCtorRef));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                attrType.Methods.Add(ctor);

                for (int f = 0; f < rng.Next(2, 5); f++)
                {
                    TypeSig ft;
                    int t = rng.Next(0, 3);
                    if (t == 0) ft = module.CorLibTypes.String;
                    else if (t == 1) ft = module.CorLibTypes.Int32;
                    else ft = module.CorLibTypes.Boolean;

                    attrType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft),
                        DnFieldAttributes.Public));
                }
            }
        }

        private void InjectPhantomMethods(ModuleDef module)
        {
            var existingTypes = module.Types.Where(t => engine.injectedTypes.Contains(t) && !t.IsInterface).ToList();
            for (int i = 0; i < PHANTOM_METHOD_COUNT; i++)
            {
                if (existingTypes.Count == 0) break;
                var host = existingTypes[rng.Next(existingTypes.Count)];
                var method = BuildPhantomComputeMethod(module);
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
            }
        }

        private void InjectPhantomFields(ModuleDef module)
        {
            var existingTypes = module.Types.Where(t => engine.injectedTypes.Contains(t) && !t.IsInterface).ToList();
            for (int i = 0; i < PHANTOM_FIELD_COUNT; i++)
            {
                if (existingTypes.Count == 0) break;
                var host = existingTypes[rng.Next(existingTypes.Count)];
                TypeSig ft;
                int t = rng.Next(0, 7);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = module.CorLibTypes.Boolean;
                else if (t == 3) ft = module.CorLibTypes.Byte;
                else if (t == 4) ft = module.CorLibTypes.Double;
                else if (t == 5) ft = new SZArraySig(module.CorLibTypes.Int32);
                else ft = new SZArraySig(module.CorLibTypes.Byte);

                host.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void InjectTrapMethods(ModuleDef module)
        {
            var existingTypes = module.Types.Where(t => engine.injectedTypes.Contains(t) &&
                !t.IsInterface).ToList();
            for (int i = 0; i < TRAP_METHOD_COUNT; i++)
            {
                if (existingTypes.Count == 0) break;
                var host = existingTypes[rng.Next(existingTypes.Count)];
                var trap = BuildTrapMethod(module);
                host.Methods.Add(trap);
                engine.injectedMethods.Add(trap);
            }
        }

        private void InjectOverloadedMethods(ModuleDef module)
        {
            var existingTypes = module.Types.Where(t => engine.injectedTypes.Contains(t) &&
                !t.IsInterface).ToList();
            for (int i = 0; i < OVERLOAD_COUNT; i++)
            {
                if (existingTypes.Count == 0) break;
                var host = existingTypes[rng.Next(existingTypes.Count)];
                string baseName = engine.MakeName();

                for (int o = 0; o < rng.Next(2, 5); o++)
                {
                    int paramCount = o + 1;
                    var paramTypes = new List<TypeSig>();
                    for (int p = 0; p < paramCount; p++)
                        paramTypes.Add(module.CorLibTypes.Int32);

                    var method = new MethodDefUser(baseName,
                        MethodSig.CreateStatic(module.CorLibTypes.Int32, paramTypes.ToArray()),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

                    method.Body = new CilBody();
                    method.Body.InitLocals = true;
                    method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
                    var il = method.Body.Instructions;

                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));

                    for (int r = 0; r < rng.Next(3, 8); r++)
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    }

                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ret));

                    host.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }
            }
        }

        private void InjectDummyGenerics(ModuleDef module)
        {
            for (int g = 0; g < DUMMY_GENERIC_COUNT; g++)
            {
                var genType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                genType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.BeforeFieldInit;

                int genParamCount = rng.Next(1, 4);
                for (int p = 0; p < genParamCount; p++)
                {
                    var gp = new GenericParamUser((ushort)p, GenericParamAttributes.NonVariant,
                        engine.MakeName());
                    genType.GenericParameters.Add(gp);
                }

                module.Types.Add(genType);
                engine.injectedTypes.Add(genType);

                for (int f = 0; f < rng.Next(3, 6); f++)
                {
                    genType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(2, 5); m++)
                {
                    var method = BuildPhantomComputeMethod(module);
                    genType.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }
            }
        }

        private void InjectMalformedNames(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                string malName = BuildMalformedName();
                var type = new TypeDefUser("", malName,
                    module.CorLibTypes.Object.TypeDefOrRef);
                type.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(type);
                engine.injectedTypes.Add(type);

                for (int f = 0; f < rng.Next(2, 5); f++)
                {
                    type.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(2, 4); m++)
                {
                    var method = BuildPhantomComputeMethod(module);
                    type.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }
            }
        }

        private void InjectCircularReferences(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(2, 4); i++)
            {
                var typeA = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                typeA.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(typeA);
                engine.injectedTypes.Add(typeA);

                var typeB = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                typeB.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(typeB);
                engine.injectedTypes.Add(typeB);

                typeA.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
                typeB.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));

                for (int m = 0; m < rng.Next(2, 4); m++)
                {
                    var methodA = BuildPhantomComputeMethod(module);
                    typeA.Methods.Add(methodA);
                    engine.injectedMethods.Add(methodA);

                    var methodB = BuildPhantomComputeMethod(module);
                    typeB.Methods.Add(methodB);
                    engine.injectedMethods.Add(methodB);
                }
            }
        }

        private void InjectDecoyResources(ModuleDef module)
        {
            for (int i = 0; i < DECOY_RESOURCE_COUNT; i++)
            {
                byte[] data = new byte[rng.Next(64, 256)];
                rng.NextBytes(data);
                var res = new EmbeddedResource(engine.MakeName(), data,
                    ManifestResourceAttributes.Private);
                module.Resources.Add(res);
            }
        }

        private void InjectPInvokeDecoys(ModuleDef module)
        {
            string[] dllNames = new string[] { "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll" };
            string[] funcNames = new string[] { "VirtualProtect", "NtQueryInformationProcess",
                "GetModuleHandle", "IsDebuggerPresent", "GetTickCount",
                "QueryPerformanceCounter", "GetCurrentProcess", "CheckRemoteDebuggerPresent" };

            var pinvokeType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            pinvokeType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed;
            module.Types.Add(pinvokeType);
            engine.injectedTypes.Add(pinvokeType);

            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                string dll = dllNames[rng.Next(dllNames.Length)];
                string func = funcNames[rng.Next(funcNames.Length)];

                var method = new MethodDefUser(engine.MakeName(),
                    MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

                method.Body = new CilBody();
                method.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                method.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                method.Body.Instructions.Add(Instruction.Create(DnOpCodes.Xor));
                method.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));

                pinvokeType.Methods.Add(method);
                engine.injectedMethods.Add(method);
            }

            for (int f = 0; f < rng.Next(4, 8); f++)
            {
                pinvokeType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void InjectModuleAttributes(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(3, 6); i++)
            {
                var dummyType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                dummyType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(dummyType);
                engine.injectedTypes.Add(dummyType);

                for (int f = 0; f < rng.Next(3, 7); f++)
                {
                    dummyType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 6); m++)
                {
                    var method = BuildPhantomComputeMethod(module);
                    dummyType.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }
            }
        }

        private MethodDef BuildPhantomComputeMethod(ModuleDef module)
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

            for (int r = 0; r < rng.Next(6, 16); r++)
            {
                int op = rng.Next(0, 8);
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
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                    case 4:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Or));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    case 5:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 6:
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

        private MethodDef BuildTrapMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Ldc_I4, rng.Next());
            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            var afterHandler = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int n = 0; n < rng.Next(3, 8); n++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                il.Add(Instruction.Create(DnOpCodes.Xor));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }

            il.Add(Instruction.Create(DnOpCodes.Leave, afterHandler));

            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterHandler));

            il.Add(afterHandler);
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

        private string BuildMalformedName()
        {
            char[] special = new char[] {
                '\u200B', '\u200C', '\u200D', '\u200E', '\u200F',
                '\u2028', '\u2029', '\u202A', '\u202B', '\u202C',
                '\uFEFF', '\u00AD', '\u034F', '\u180E'
            };

            int length = rng.Next(8, 16);
            char[] buf = new char[length];
            for (int i = 0; i < length; i++)
            {
                if (rng.Next(0, 3) == 0)
                    buf[i] = special[rng.Next(special.Length)];
                else
                    buf[i] = engine.charset[rng.Next(engine.charset.Length)];
            }
            return new string(buf);
        }
    }
}

