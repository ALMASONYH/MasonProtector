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
    internal class FieldEncryptionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int KEY_POOL_SIZE = 24;
        private FieldDef[] keyFields;
        private int[] keyValues;
        private TypeDef keyHost;
        private List<MethodDef> transformMethods;

        internal FieldEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyFieldEncryption(ModuleDef module, TypeDef modType)
        {
            keyFields = new FieldDef[KEY_POOL_SIZE];
            keyValues = new int[KEY_POOL_SIZE];
            transformMethods = new List<MethodDef>();

            keyHost = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            keyHost.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(keyHost);
            engine.injectedTypes.Add(keyHost);

            for (int i = 0; i < KEY_POOL_SIZE; i++)
            {
                keyValues[i] = rng.Next(100000, int.MaxValue / 2);
                keyFields[i] = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Assembly | DnFieldAttributes.Static);
                keyHost.Fields.Add(keyFields[i]);
            }

            for (int d = 0; d < rng.Next(8, 18); d++)
            {
                keyHost.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }

            for (int t = 0; t < 18; t++)
            {
                var tm = BuildTransformMethod(module, t);
                keyHost.Methods.Add(tm);
                engine.injectedMethods.Add(tm);
                transformMethods.Add(tm);
            }

            for (int f = 0; f < 12; f++)
            {
                var fake = BuildFakeTransform(module);
                keyHost.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }

            int counter = 0;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    try
                    {
                        counter += ProtectFieldAccess(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }

            if (counter > 0)
            {
                var initMethod = BuildKeyInitializer(module);
                keyHost.Methods.Add(initMethod);
                engine.injectedMethods.Add(initMethod);
                engine.InjectCallInCctor(module, modType, initMethod);
            }
        }

        private int ProtectFieldAccess(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            int encrypted = 0;

            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode == DnOpCodes.Ldsfld)
                {
                    var field = il[i].Operand as FieldDef;
                    if (field == null) continue;
                    if (field.DeclaringType == null) continue;
                    if (engine.injectedTypes.Contains(field.DeclaringType)) continue;
                    if (field.FieldType == null) continue;

                    string typeName = field.FieldType.FullName;
                    if (typeName != "System.Int32") continue;
                    if (rng.Next(0, 2) != 0) continue;

                    int keyIdx = rng.Next(0, KEY_POOL_SIZE);
                    int transformIdx = rng.Next(0, transformMethods.Count);

                    var postInsts = new List<Instruction>();
                    postInsts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyIdx]));
                    postInsts.Add(Instruction.Create(DnOpCodes.Call, transformMethods[transformIdx]));

                    if (rng.Next(0, 2) == 0)
                    {
                        int keyIdx2 = rng.Next(0, KEY_POOL_SIZE);
                        int transformIdx2 = rng.Next(0, transformMethods.Count);
                        postInsts.Add(Instruction.Create(DnOpCodes.Ldsfld, keyFields[keyIdx2]));
                        postInsts.Add(Instruction.Create(DnOpCodes.Call, transformMethods[transformIdx2]));
                    }

                    for (int j = 0; j < postInsts.Count; j++)
                        il.Insert(i + 1 + j, postInsts[j]);
                    i += postInsts.Count;
                    encrypted++;
                }
            }

            return encrypted;
        }

        private MethodDef BuildTransformMethod(ModuleDef module, int variant)
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

            switch (variant % 6)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Mul));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 3:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
                default:
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    il.Add(Instruction.Create(DnOpCodes.Mul));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ret));
                    break;
            }

            return method;
        }

        private MethodDef BuildFakeTransform(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDefUser BuildKeyInitializer(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            for (int i = 0; i < KEY_POOL_SIZE; i++)
            {
                int pattern = rng.Next(0, 3);
                switch (pattern)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, keyValues[i]));
                        break;
                    case 1:
                        int k = rng.Next(int.MinValue, int.MaxValue);
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ keyValues[i]));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~keyValues[i]));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        break;
                }
                il.Add(Instruction.Create(DnOpCodes.Stsfld, keyFields[i]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

