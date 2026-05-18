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
    internal class ControlFlowFlattening2Protection
    {
        private Obfuscation engine;
        private Random rng;

        private const int DISPATCH_TABLE_COUNT = 12;
        private const int DISPATCH_TABLE_SIZE = 384;
        private const int DISPATCH_KEY_COUNT = 24;
        private const int DISPATCH_DECODER_COUNT = 18;
        private const int DISPATCH_FAKE_COUNT = 24;
        private const int DISPATCH_DECOY_TYPE_COUNT = 14;

        private TypeDef dispatchType;
        private TypeDef computeType;
        private TypeDef helperType;
        private List<FieldDef> dispatchTables;
        private List<int[]> dispatchData;
        private List<FieldDef> keyFields;
        private int[] keyValues;
        private List<MethodDef> decoderMethods;
        private FieldDef stateField;
        private int stateInitValue;
        private FieldDef xorField;
        private int xorValue;
        private FieldDef addField;
        private int addValue;
        private FieldDef mulField;
        private int mulValue;

        internal ControlFlowFlattening2Protection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyControlFlowFlattening2(ModuleDef module, TypeDef modType)
        {
            dispatchTables = new List<FieldDef>();
            dispatchData = new List<int[]>();
            keyFields = new List<FieldDef>();
            keyValues = new int[DISPATCH_KEY_COUNT];
            decoderMethods = new List<MethodDef>();

            CreateDispatchType(module);
            CreateComputeType(module);
            CreateHelperType(module);
            CreateDispatchTables(module);
            CreateKeyFields(module);
            CreateDecoderMethods(module);
            CreateFakeMethods(module);
            CreateDecoyTypes(module);
            InjectDecoyFieldNoise(module);

            var init = BuildInitializer(module);
            dispatchType.Methods.Add(init);
            engine.injectedMethods.Add(init);
            engine.InjectCallInCctor(module, modType, init);
        }

        private void CreateDispatchType(ModuleDef module)
        {
            dispatchType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            dispatchType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(dispatchType);
            engine.injectedTypes.Add(dispatchType);

            stateInitValue = rng.Next(100000, int.MaxValue / 2);
            stateField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            dispatchType.Fields.Add(stateField);

            xorValue = rng.Next(1, int.MaxValue / 2);
            xorField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            dispatchType.Fields.Add(xorField);

            addValue = rng.Next(1, int.MaxValue / 4);
            addField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            dispatchType.Fields.Add(addField);

            mulValue = rng.Next(3, 127) | 1;
            mulField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            dispatchType.Fields.Add(mulField);

            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                dispatchType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateComputeType(ModuleDef module)
        {
            computeType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            computeType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(computeType);
            engine.injectedTypes.Add(computeType);

            for (int i = 0; i < rng.Next(6, 12); i++)
            {
                TypeSig ft;
                int t = rng.Next(0, 4);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = module.CorLibTypes.Boolean;
                else ft = new SZArraySig(module.CorLibTypes.Int32);

                computeType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateHelperType(ModuleDef module)
        {
            helperType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            helperType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(helperType);
            engine.injectedTypes.Add(helperType);

            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                helperType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateDispatchTables(ModuleDef module)
        {
            for (int d = 0; d < DISPATCH_TABLE_COUNT; d++)
            {
                TypeDef host;
                if (d % 3 == 0) host = dispatchType;
                else if (d % 3 == 1) host = computeType;
                else host = helperType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                dispatchTables.Add(field);

                var data = new int[DISPATCH_TABLE_SIZE];
                for (int i = 0; i < DISPATCH_TABLE_SIZE; i++)
                    data[i] = rng.Next(int.MinValue, int.MaxValue);
                dispatchData.Add(data);
            }
        }

        private void CreateKeyFields(ModuleDef module)
        {
            for (int k = 0; k < DISPATCH_KEY_COUNT; k++)
            {
                keyValues[k] = rng.Next(int.MinValue, int.MaxValue);
                TypeDef host;
                if (k % 3 == 0) host = dispatchType;
                else if (k % 3 == 1) host = computeType;
                else host = helperType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                keyFields.Add(field);
            }
        }

        private void CreateDecoderMethods(ModuleDef module)
        {
            for (int d = 0; d < DISPATCH_DECODER_COUNT; d++)
            {
                var method = BuildDecoderMethod(module, d);
                TypeDef host;
                if (d % 3 == 0) host = dispatchType;
                else if (d % 3 == 1) host = computeType;
                else host = helperType;
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                decoderMethods.Add(method);
            }
        }

        private void CreateFakeMethods(ModuleDef module)
        {
            TypeDef[] hosts = new TypeDef[] { dispatchType, computeType, helperType };
            for (int f = 0; f < DISPATCH_FAKE_COUNT; f++)
            {
                var host = hosts[f % hosts.Length];
                var fake = BuildFakeDecoder(module);
                host.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }
        }

        private void CreateDecoyTypes(ModuleDef module)
        {
            for (int d = 0; d < DISPATCH_DECOY_TYPE_COUNT; d++)
            {
                var decoy = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                decoy.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(decoy);
                engine.injectedTypes.Add(decoy);

                for (int f = 0; f < rng.Next(4, 10); f++)
                {
                    TypeSig ft;
                    int t = rng.Next(0, 5);
                    if (t == 0) ft = module.CorLibTypes.Int32;
                    else if (t == 1) ft = module.CorLibTypes.Int64;
                    else if (t == 2) ft = module.CorLibTypes.Boolean;
                    else if (t == 3) ft = module.CorLibTypes.Byte;
                    else ft = module.CorLibTypes.Double;

                    decoy.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 8); m++)
                {
                    var decoyMethod = BuildDecoyCompute(module);
                    decoy.Methods.Add(decoyMethod);
                    engine.injectedMethods.Add(decoyMethod);
                }
            }
        }

        private void InjectDecoyFieldNoise(ModuleDef module)
        {
            TypeDef[] hosts = new TypeDef[] { dispatchType, computeType, helperType };
            for (int i = 0; i < rng.Next(10, 20); i++)
            {
                var host = hosts[rng.Next(hosts.Length)];
                TypeSig ft;
                int t = rng.Next(0, 6);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Int64;
                else if (t == 2) ft = module.CorLibTypes.Boolean;
                else if (t == 3) ft = new SZArraySig(module.CorLibTypes.Int32);
                else if (t == 4) ft = module.CorLibTypes.Byte;
                else ft = new SZArraySig(module.CorLibTypes.Byte);

                host.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private MethodDef BuildDecoderMethod(ModuleDef module, int variant)
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

            switch (variant % 6)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, stateField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, xorField));
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
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, addField));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, mulField));
                    il.Add(Instruction.Create(DnOpCodes.Mul));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, stateField));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, xorField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, addField));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
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

        private MethodDef BuildFakeDecoder(ModuleDef module)
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
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
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
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildDecoyCompute(ModuleDef module)
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
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            for (int r = 0; r < rng.Next(6, 14); r++)
            {
                int op = rng.Next(0, 7);
                switch (op)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
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
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                    case 4:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    case 5:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Or));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
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

        private MethodDefUser BuildInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, stateInitValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stateField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, xorValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, xorField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, addValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, addField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, mulValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, mulField));

            for (int k = 0; k < DISPATCH_KEY_COUNT; k++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, keyValues[k]));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, keyFields[k]));
            }

            for (int d = 0; d < DISPATCH_TABLE_COUNT; d++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, DISPATCH_TABLE_SIZE));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));

                for (int i = 0; i < DISPATCH_TABLE_SIZE; i++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(engine.LoadInt(i));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, dispatchData[d][i]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                }

                il.Add(Instruction.Create(DnOpCodes.Stsfld, dispatchTables[d]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

