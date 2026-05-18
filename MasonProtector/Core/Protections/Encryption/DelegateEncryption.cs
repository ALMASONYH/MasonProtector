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
    internal class DelegateEncryptionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int DELEGATE_POOL_COUNT = 18;
        private const int DELEGATE_FAKE_COUNT = 32;
        private const int DELEGATE_DECOY_FIELD_COUNT = 36;
        private const int DELEGATE_KEY_COUNT = 24;
        private const int DELEGATE_EVALUATOR_COUNT = 28;

        private List<TypeDef> delegateHosts;
        private List<FieldDef> keyFields;
        private int[] keyValues;
        private List<MethodDef> evaluatorMethods;
        private TypeDef registryType;
        private TypeDef cacheType;
        private TypeDef resolverType;
        private FieldDef masterKeyField;
        private int masterKeyValue;
        private FieldDef auxField;
        private int auxValue;
        private FieldDef saltField;
        private int saltValue;
        private FieldDef counterField;
        private int counterValue;

        internal DelegateEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyDelegateEncryption(ModuleDef module, TypeDef modType)
        {
            delegateHosts = new List<TypeDef>();
            keyFields = new List<FieldDef>();
            keyValues = new int[DELEGATE_KEY_COUNT];
            evaluatorMethods = new List<MethodDef>();

            CreateRegistryType(module);
            CreateCacheType(module);
            CreateResolverType(module);
            CreateDelegateHosts(module);
            CreateKeyFields(module);
            CreateEvaluatorMethods(module);
            CreateFakeMethods(module);
            InjectDecoyFields(module);
            InjectDecoyNestedTypes(module);

            var init = BuildInitializer(module);
            registryType.Methods.Add(init);
            engine.injectedMethods.Add(init);
            engine.InjectCallInCctor(module, modType, init);
        }

        private void CreateRegistryType(ModuleDef module)
        {
            registryType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            registryType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(registryType);
            engine.injectedTypes.Add(registryType);

            masterKeyValue = rng.Next(100000, int.MaxValue / 2);
            masterKeyField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            registryType.Fields.Add(masterKeyField);

            auxValue = rng.Next(100000, int.MaxValue / 2);
            auxField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            registryType.Fields.Add(auxField);

            for (int i = 0; i < rng.Next(5, 10); i++)
            {
                TypeSig ft;
                int t = rng.Next(0, 4);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = module.CorLibTypes.Boolean;
                else ft = new SZArraySig(module.CorLibTypes.Int32);

                registryType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateCacheType(ModuleDef module)
        {
            cacheType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            cacheType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(cacheType);
            engine.injectedTypes.Add(cacheType);

            saltValue = rng.Next(1, 65536);
            saltField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            cacheType.Fields.Add(saltField);

            counterValue = rng.Next(1, int.MaxValue / 4);
            counterField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            cacheType.Fields.Add(counterField);

            for (int i = 0; i < rng.Next(6, 12); i++)
            {
                TypeSig ft;
                int t = rng.Next(0, 5);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = module.CorLibTypes.String;
                else if (t == 3) ft = module.CorLibTypes.Boolean;
                else ft = new SZArraySig(module.CorLibTypes.Byte);

                cacheType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateResolverType(ModuleDef module)
        {
            resolverType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            resolverType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(resolverType);
            engine.injectedTypes.Add(resolverType);

            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                TypeSig ft;
                int t = rng.Next(0, 4);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = new SZArraySig(module.CorLibTypes.Int32);
                else ft = module.CorLibTypes.Double;

                resolverType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateDelegateHosts(ModuleDef module)
        {
            for (int h = 0; h < DELEGATE_POOL_COUNT; h++)
            {
                var host = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(host);
                engine.injectedTypes.Add(host);
                delegateHosts.Add(host);

                for (int f = 0; f < rng.Next(4, 8); f++)
                {
                    TypeSig ft;
                    int t = rng.Next(0, 4);
                    if (t == 0) ft = module.CorLibTypes.Int32;
                    else if (t == 1) ft = module.CorLibTypes.Int64;
                    else if (t == 2) ft = module.CorLibTypes.Boolean;
                    else ft = module.CorLibTypes.Byte;

                    host.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 6); m++)
                {
                    var decoyMethod = BuildDecoyMethod(module);
                    host.Methods.Add(decoyMethod);
                    engine.injectedMethods.Add(decoyMethod);
                }
            }
        }

        private void CreateKeyFields(ModuleDef module)
        {
            for (int k = 0; k < DELEGATE_KEY_COUNT; k++)
            {
                keyValues[k] = rng.Next(int.MinValue, int.MaxValue);
                TypeDef host;
                if (k % 4 == 0) host = registryType;
                else if (k % 4 == 1) host = cacheType;
                else if (k % 4 == 2) host = resolverType;
                else host = delegateHosts[k % delegateHosts.Count];

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                keyFields.Add(field);
            }
        }

        private void CreateEvaluatorMethods(ModuleDef module)
        {
            for (int e = 0; e < DELEGATE_EVALUATOR_COUNT; e++)
            {
                var method = BuildEvaluatorMethod(module, e);
                TypeDef host;
                if (e % 4 == 0) host = registryType;
                else if (e % 4 == 1) host = cacheType;
                else if (e % 4 == 2) host = resolverType;
                else host = delegateHosts[e % delegateHosts.Count];
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                evaluatorMethods.Add(method);
            }
        }

        private void CreateFakeMethods(ModuleDef module)
        {
            TypeDef[] allHosts = new TypeDef[] { registryType, cacheType, resolverType };
            for (int f = 0; f < DELEGATE_FAKE_COUNT; f++)
            {
                TypeDef host;
                if (f < allHosts.Length) host = allHosts[f];
                else host = delegateHosts[f % delegateHosts.Count];

                var fake = BuildFakeEvaluator(module);
                host.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }
        }

        private void InjectDecoyFields(ModuleDef module)
        {
            var allTypes = new List<TypeDef>();
            allTypes.Add(registryType);
            allTypes.Add(cacheType);
            allTypes.Add(resolverType);
            allTypes.AddRange(delegateHosts);

            for (int i = 0; i < DELEGATE_DECOY_FIELD_COUNT; i++)
            {
                var host = allTypes[rng.Next(allTypes.Count)];
                TypeSig ft;
                int t = rng.Next(0, 6);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = module.CorLibTypes.Boolean;
                else if (t == 3) ft = module.CorLibTypes.Byte;
                else if (t == 4) ft = new SZArraySig(module.CorLibTypes.Int32);
                else ft = module.CorLibTypes.Double;

                host.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void InjectDecoyNestedTypes(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(2, 5); i++)
            {
                var parent = delegateHosts[rng.Next(delegateHosts.Count)];
                var nested = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                nested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                parent.NestedTypes.Add(nested);
                engine.injectedTypes.Add(nested);

                for (int f = 0; f < rng.Next(3, 6); f++)
                {
                    nested.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(2, 4); m++)
                {
                    var decoy = BuildDecoyMethod(module);
                    nested.Methods.Add(decoy);
                    engine.injectedMethods.Add(decoy);
                }
            }
        }

        private MethodDef BuildEvaluatorMethod(ModuleDef module, int variant)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            switch (variant % 5)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, masterKeyField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, auxField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, saltField));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, counterField));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, masterKeyField));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, auxField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
            }

            for (int n = 0; n < rng.Next(2, 5); n++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                il.Add(Instruction.Create(DnOpCodes.Pop));
                il.Add(Instruction.Create(DnOpCodes.Pop));
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildFakeEvaluator(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int n = 0; n < rng.Next(4, 10); n++)
            {
                int op = rng.Next(0, 5);
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
                        il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildDecoyMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int r = 0; r < rng.Next(5, 12); r++)
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
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDefUser BuildInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterKeyValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, masterKeyField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, auxValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, auxField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, saltValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, saltField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, counterValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, counterField));

            for (int k = 0; k < DELEGATE_KEY_COUNT; k++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, keyValues[k]));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, keyFields[k]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

