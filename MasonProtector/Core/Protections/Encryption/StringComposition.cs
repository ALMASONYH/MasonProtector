using System;
using System.Collections.Generic;
using System.Linq;
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
    internal class StringCompositionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int CHAR_TABLE_COUNT = 16;
        private const int CHAR_TABLE_SIZE = 640;
        private const int BUILDER_METHOD_COUNT = 28;
        private const int FAKE_BUILDER_COUNT = 22;
        private const int KEY_FIELD_COUNT = 24;
        private const int CHAR_RESOLVER_COUNT = 22;

        private TypeDef composerType;
        private TypeDef storageType;
        private TypeDef resolverType;
        private List<FieldDef> charTables;
        private List<int[]> charTableData;
        private List<FieldDef> keyFields;
        private int[] keyValues;
        private List<MethodDef> builderMethods;
        private List<MethodDef> charResolvers;
        private FieldDef masterXorField;
        private int masterXorValue;
        private FieldDef shiftField;
        private int shiftValue;
        private FieldDef saltField;
        private int saltValue;

        private IMethod concatMethod;
        private IMethod charToStringMethod;
        private IMethod substringMethod;
        private TypeRef stringBuilderRef;
        private IMethod sbCtorMethod;
        private IMethod sbAppendCharMethod;
        private IMethod sbToStringMethod;

        internal StringCompositionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyStringComposition(ModuleDef module, TypeDef modType)
        {
            charTables = new List<FieldDef>();
            charTableData = new List<int[]>();
            keyFields = new List<FieldDef>();
            keyValues = new int[KEY_FIELD_COUNT];
            builderMethods = new List<MethodDef>();
            charResolvers = new List<MethodDef>();

            ResolveFrameworkMethods(module);
            CreateComposerType(module);
            CreateStorageType(module);
            CreateResolverType(module);
            CreateCharTables(module);
            CreateKeyFields(module);
            CreateBuilderMethods(module);
            CreateCharResolvers(module);
            CreateFakeBuilders(module);
            CreateFakeFields(module);

            int counter = 0;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    try
                    {
                        counter += DecomposeStrings(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            if (counter > 0)
            {
                var init = BuildInitializer(module);
                composerType.Methods.Add(init);
                engine.injectedMethods.Add(init);
                engine.InjectCallInCctor(module, modType, init);
            }
        }

        private void ResolveFrameworkMethods(ModuleDef module)
        {
            var stringRef = module.CorLibTypes.String.TypeDefOrRef;

            concatMethod = new MemberRefUser(module, "Concat",
                MethodSig.CreateStatic(module.CorLibTypes.String,
                    module.CorLibTypes.String, module.CorLibTypes.String),
                stringRef);

            charToStringMethod = new MemberRefUser(module, "ToString",
                MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Char),
                module.CorLibTypes.GetTypeRef("System", "Char"));

            substringMethod = new MemberRefUser(module, "Substring",
                MethodSig.CreateInstance(module.CorLibTypes.String,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                stringRef);

            stringBuilderRef = new TypeRefUser(module, "System.Text", "StringBuilder",
                module.CorLibTypes.AssemblyRef);

            sbCtorMethod = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                stringBuilderRef);

            sbAppendCharMethod = new MemberRefUser(module, "Append",
                MethodSig.CreateInstance(new ClassSig(stringBuilderRef), module.CorLibTypes.Char),
                stringBuilderRef);

            sbToStringMethod = new MemberRefUser(module, "ToString",
                MethodSig.CreateInstance(module.CorLibTypes.String),
                stringBuilderRef);
        }

        private void CreateComposerType(ModuleDef module)
        {
            composerType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            composerType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(composerType);
            engine.injectedTypes.Add(composerType);

            masterXorValue = rng.Next(1, int.MaxValue / 2);
            masterXorField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            composerType.Fields.Add(masterXorField);

            shiftValue = rng.Next(1, 16);
            shiftField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            composerType.Fields.Add(shiftField);

            saltValue = rng.Next(100, 65536);
            saltField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            composerType.Fields.Add(saltField);

            for (int i = 0; i < rng.Next(4, 8); i++)
            {
                composerType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateStorageType(ModuleDef module)
        {
            storageType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            storageType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(storageType);
            engine.injectedTypes.Add(storageType);

            for (int i = 0; i < rng.Next(6, 10); i++)
            {
                storageType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
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

            for (int i = 0; i < rng.Next(3, 7); i++)
            {
                resolverType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int64),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void CreateCharTables(ModuleDef module)
        {
            for (int t = 0; t < CHAR_TABLE_COUNT; t++)
            {
                TypeDef host;
                if (t % 3 == 0) host = composerType;
                else if (t % 3 == 1) host = storageType;
                else host = resolverType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                charTables.Add(field);

                var data = new int[CHAR_TABLE_SIZE];
                for (int i = 0; i < CHAR_TABLE_SIZE; i++)
                    data[i] = rng.Next(int.MinValue, int.MaxValue);
                charTableData.Add(data);
            }
        }

        private void CreateKeyFields(ModuleDef module)
        {
            for (int k = 0; k < KEY_FIELD_COUNT; k++)
            {
                keyValues[k] = rng.Next(int.MinValue, int.MaxValue);
                TypeDef host;
                if (k % 3 == 0) host = composerType;
                else if (k % 3 == 1) host = storageType;
                else host = resolverType;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                host.Fields.Add(field);
                keyFields.Add(field);
            }
        }

        private void CreateBuilderMethods(ModuleDef module)
        {
            for (int b = 0; b < BUILDER_METHOD_COUNT; b++)
            {
                var method = BuildCharDecoder(module, b);
                TypeDef host;
                if (b % 3 == 0) host = composerType;
                else if (b % 3 == 1) host = storageType;
                else host = resolverType;
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                builderMethods.Add(method);
            }
        }

        private void CreateCharResolvers(ModuleDef module)
        {
            for (int r = 0; r < CHAR_RESOLVER_COUNT; r++)
            {
                var method = BuildCharResolver(module, r);
                TypeDef host;
                if (r % 2 == 0) host = composerType;
                else host = resolverType;
                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
                charResolvers.Add(method);
            }
        }

        private void CreateFakeBuilders(ModuleDef module)
        {
            for (int f = 0; f < FAKE_BUILDER_COUNT; f++)
            {
                var fake = BuildFakeCharDecoder(module);
                TypeDef host;
                if (f % 3 == 0) host = composerType;
                else if (f % 3 == 1) host = storageType;
                else host = resolverType;
                host.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }
        }

        private void CreateFakeFields(ModuleDef module)
        {
            TypeDef[] hosts = new TypeDef[] { composerType, storageType, resolverType };
            for (int i = 0; i < rng.Next(6, 12); i++)
            {
                var host = hosts[rng.Next(hosts.Length)];
                TypeSig ft;
                int t = rng.Next(0, 4);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = module.CorLibTypes.Boolean;
                else if (t == 2) ft = module.CorLibTypes.Byte;
                else ft = new SZArraySig(module.CorLibTypes.Int32);

                host.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private int DecomposeStrings(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            int decomposed = 0;

            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode != DnOpCodes.Ldstr) continue;
                string str = il[i].Operand as string;
                if (str == null || str.Length == 0 || str.Length > 32) continue;
                if (rng.Next(0, 3) != 0) continue;

                List<Instruction> replacement = null;
                if (str.Length <= 3)
                    replacement = BuildShortStringCompose(module, str);
                else if (str.Length <= 8)
                    replacement = BuildMediumStringCompose(module, str);
                else
                    replacement = BuildLongStringCompose(module, str);

                if (replacement == null || replacement.Count == 0) continue;

                il[i].OpCode = replacement[0].OpCode;
                il[i].Operand = replacement[0].Operand;
                for (int j = 1; j < replacement.Count; j++)
                    il.Insert(i + j, replacement[j]);
                i += replacement.Count - 1;
                decomposed++;
            }

            return decomposed;
        }

        private List<Instruction> BuildShortStringCompose(ModuleDef module, string str)
        {
            var insts = new List<Instruction>();
            if (str.Length == 1)
            {
                int charVal = (int)str[0];
                int k = rng.Next(0, KEY_FIELD_COUNT);
                int encoded = charVal ^ keyValues[k];
                insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[k]));
                insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
                insts.Add(Instruction.Create(DnOpCodes.Xor));
                insts.Add(Instruction.Create(DnOpCodes.Conv_U2));
                insts.Add(Instruction.Create(DnOpCodes.Call, charToStringMethod));
            }
            else
            {
                insts.AddRange(BuildCharToString(module, str[0]));
                for (int c = 1; c < str.Length; c++)
                {
                    insts.AddRange(BuildCharToString(module, str[c]));
                    insts.Add(Instruction.Create(DnOpCodes.Call, concatMethod));
                }
            }
            return insts;
        }

        private List<Instruction> BuildMediumStringCompose(ModuleDef module, string str)
        {
            var insts = new List<Instruction>();
            int half = str.Length / 2;
            string left = str.Substring(0, half);
            string right = str.Substring(half);

            insts.AddRange(BuildShortStringCompose(module, left.Substring(0, 1)));
            for (int c = 1; c < left.Length; c++)
            {
                insts.AddRange(BuildCharToString(module, left[c]));
                insts.Add(Instruction.Create(DnOpCodes.Call, concatMethod));
            }

            insts.AddRange(BuildCharToString(module, right[0]));
            for (int c = 1; c < right.Length; c++)
            {
                insts.AddRange(BuildCharToString(module, right[c]));
                insts.Add(Instruction.Create(DnOpCodes.Call, concatMethod));
            }

            insts.Add(Instruction.Create(DnOpCodes.Call, concatMethod));
            return insts;
        }

        private List<Instruction> BuildLongStringCompose(ModuleDef module, string str)
        {
            var insts = new List<Instruction>();
            int third = str.Length / 3;
            string p1 = str.Substring(0, third);
            string p2 = str.Substring(third, third);
            string p3 = str.Substring(third * 2);

            insts.AddRange(BuildPartCompose(module, p1));
            insts.AddRange(BuildPartCompose(module, p2));
            insts.Add(Instruction.Create(DnOpCodes.Call, concatMethod));
            insts.AddRange(BuildPartCompose(module, p3));
            insts.Add(Instruction.Create(DnOpCodes.Call, concatMethod));
            return insts;
        }

        private List<Instruction> BuildPartCompose(ModuleDef module, string part)
        {
            var insts = new List<Instruction>();
            if (part.Length == 0) return insts;

            insts.AddRange(BuildCharToString(module, part[0]));
            for (int c = 1; c < part.Length; c++)
            {
                insts.AddRange(BuildCharToString(module, part[c]));
                insts.Add(Instruction.Create(DnOpCodes.Call, concatMethod));
            }
            return insts;
        }

        private List<Instruction> BuildCharToString(ModuleDef module, char ch)
        {
            var insts = new List<Instruction>();
            int charVal = (int)ch;
            int pattern = rng.Next(0, 4);

            switch (pattern)
            {
                case 0:
                {
                    int k = rng.Next(0, KEY_FIELD_COUNT);
                    int encoded = charVal ^ keyValues[k];
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[k]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, encoded));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    insts.Add(Instruction.Create(DnOpCodes.Call, charToStringMethod));
                    break;
                }
                case 1:
                {
                    int diff = charVal ^ masterXorValue;
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, masterXorField));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
                    insts.Add(Instruction.Create(DnOpCodes.Xor));
                    insts.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    insts.Add(Instruction.Create(DnOpCodes.Call, charToStringMethod));
                    break;
                }
                case 2:
                {
                    int k = rng.Next(0, KEY_FIELD_COUNT);
                    int diff = charVal - keyValues[k];
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[k]));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    insts.Add(Instruction.Create(DnOpCodes.Call, charToStringMethod));
                    break;
                }
                default:
                {
                    int diff = charVal - saltValue;
                    insts.Add(Instruction.Create(DnOpCodes.Ldsfld, saltField));
                    insts.Add(Instruction.Create(DnOpCodes.Ldc_I4, diff));
                    insts.Add(Instruction.Create(DnOpCodes.Add));
                    insts.Add(Instruction.Create(DnOpCodes.Conv_U2));
                    insts.Add(Instruction.Create(DnOpCodes.Call, charToStringMethod));
                    break;
                }
            }

            return insts;
        }

        private MethodDef BuildCharDecoder(ModuleDef module, int variant)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            switch (variant % 5)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, masterXorField));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
            }

            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildCharResolver(ModuleDef module, int variant)
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
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));

            switch (variant % 4)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    break;
            }

            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildFakeCharDecoder(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int n = 0; n < rng.Next(2, 6); n++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                int op = rng.Next(0, 3);
                if (op == 0) il.Add(Instruction.Create(DnOpCodes.Xor));
                else if (op == 1) il.Add(Instruction.Create(DnOpCodes.Add));
                else il.Add(Instruction.Create(DnOpCodes.Sub));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
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

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, masterXorValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, masterXorField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, shiftValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, shiftField));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, saltValue));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, saltField));

            for (int k = 0; k < KEY_FIELD_COUNT; k++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, keyValues[k]));
                il.Add(Instruction.Create(DnOpCodes.Stsfld, keyFields[k]));
            }

            for (int t = 0; t < CHAR_TABLE_COUNT; t++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, CHAR_TABLE_SIZE));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));

                for (int i = 0; i < CHAR_TABLE_SIZE; i++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(engine.LoadInt(i));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, charTableData[t][i]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
                }

                il.Add(Instruction.Create(DnOpCodes.Stsfld, charTables[t]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

