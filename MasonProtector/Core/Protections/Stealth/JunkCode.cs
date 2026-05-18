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
    internal class JunkCodeProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal JunkCodeProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyJunkCode(ModuleDef module, int count)
        {
            int nsPoolSize = Math.Max(2, count / 3);
            var nsPool = new List<string>();
            for (int i = 0; i < nsPoolSize; i++)
                nsPool.Add(BuildJunkNamespace());

            for (int c = 0; c < count; c++)
            {
                string ns = (rng.Next(0, 3) == 0)
                    ? BuildJunkNamespace()
                    : nsPool[rng.Next(0, nsPool.Count)];

                var junkClass = new TypeDefUser(ns, engine.MakeJunkName(rng.Next(8, 20)),
                    module.CorLibTypes.Object.TypeDefOrRef);
                junkClass.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

                PopulateJunkMembers(module, junkClass);

                int nestedCount = rng.Next(2, 8);
                for (int n = 0; n < nestedCount; n++)
                {
                    var nested = new TypeDefUser("", engine.MakeJunkName(rng.Next(8, 18)),
                        module.CorLibTypes.Object.TypeDefOrRef);
                    nested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Sealed |
                        DnTypeAttributes.BeforeFieldInit;
                    PopulateJunkMembers(module, nested);
                    junkClass.NestedTypes.Add(nested);
                    engine.injectedTypes.Add(nested);

                    if (rng.Next(0, 3) == 0)
                    {
                        var deeper = new TypeDefUser("", engine.MakeJunkName(rng.Next(8, 18)),
                            module.CorLibTypes.Object.TypeDefOrRef);
                        deeper.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Sealed |
                            DnTypeAttributes.BeforeFieldInit;
                        PopulateJunkMembers(module, deeper);
                        nested.NestedTypes.Add(deeper);
                        engine.injectedTypes.Add(deeper);
                    }
                }

                module.Types.Add(junkClass);
                engine.injectedTypes.Add(junkClass);
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (rng.Next(0, 2) != 0) continue;
                    try { InjectJunkInstructions(module, method); } catch { }
                }
            }
        }

        private string BuildJunkNamespace()
        {
            int segs = rng.Next(1, 4);
            var sb = new StringBuilder();
            for (int i = 0; i < segs; i++)
            {
                if (i > 0) sb.Append('.');
                sb.Append(engine.MakeJunkName(rng.Next(5, 12)));
            }
            return sb.ToString();
        }

        private void PopulateJunkMembers(ModuleDef module, TypeDef junkClass)
        {
            int fieldCount = rng.Next(4, 14);
            for (int f = 0; f < fieldCount; f++)
            {
                TypeSig fieldType;
                switch (rng.Next(0, 6))
                {
                    case 0: fieldType = module.CorLibTypes.Int32; break;
                    case 1: fieldType = module.CorLibTypes.String; break;
                    case 2: fieldType = module.CorLibTypes.Boolean; break;
                    case 3: fieldType = module.CorLibTypes.Double; break;
                    case 4: fieldType = new SZArraySig(module.CorLibTypes.Byte); break;
                    default: fieldType = module.CorLibTypes.Int64; break;
                }

                junkClass.Fields.Add(new FieldDefUser(engine.MakeJunkName(rng.Next(6, 14)),
                    new FieldSig(fieldType),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }

            int methodCount = rng.Next(3, 9);
            for (int m = 0; m < methodCount; m++)
            {
                var junkMethod = BuildJunkMethod(module, junkClass);
                junkClass.Methods.Add(junkMethod);
                engine.injectedMethods.Add(junkMethod);
            }
        }

        private MethodDef BuildJunkMethod(ModuleDef module, TypeDef owner)
        {
            TypeSig retType;
            switch (rng.Next(0, 4))
            {
                case 0: retType = module.CorLibTypes.Void; break;
                case 1: retType = module.CorLibTypes.Int32; break;
                case 2: retType = module.CorLibTypes.Boolean; break;
                default: retType = module.CorLibTypes.String; break;
            }

            int paramCount = rng.Next(0, 3);
            var paramTypes = new TypeSig[paramCount];
            for (int i = 0; i < paramCount; i++)
            {
                switch (rng.Next(0, 3))
                {
                    case 0: paramTypes[i] = module.CorLibTypes.Int32; break;
                    case 1: paramTypes[i] = module.CorLibTypes.String; break;
                    default: paramTypes[i] = module.CorLibTypes.Boolean; break;
                }
            }

            var method = new MethodDefUser(engine.MakeJunkName(rng.Next(8, 16)),
                MethodSig.CreateStatic(retType, paramTypes),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            int junkOps = rng.Next(12, 45);
            for (int j = 0; j < junkOps; j++)
            {
                switch (rng.Next(0, 8))
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(int.MinValue, int.MaxValue)));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 1:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 999)));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 999)));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 4:
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 99)));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 99)));
                        il.Add(Instruction.Create(DnOpCodes.Mul));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Nop));
                        break;
                }
            }

            if (retType.FullName == "System.Void")
            {
                il.Add(Instruction.Create(DnOpCodes.Ret));
            }
            else if (retType.FullName == "System.Int32")
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ret));
            }
            else if (retType.FullName == "System.Boolean")
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                il.Add(Instruction.Create(DnOpCodes.Ret));
            }
            else
            {
                il.Add(Instruction.Create(DnOpCodes.Ldstr, ""));
                il.Add(Instruction.Create(DnOpCodes.Ret));
            }

            return method;
        }

        private void InjectJunkInstructions(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            var safe = engine.FindSafeInsertPositions(il, method.Body.ExceptionHandlers);
            if (safe.Count == 0) return;

            int injectCount = Math.Min(rng.Next(4, 12), safe.Count);
            for (int n = 0; n < injectCount; n++)
            {
                int pick = rng.Next(0, safe.Count);
                int pos = safe[pick];
                safe.RemoveAt(pick);
                if (pos >= il.Count) continue;

                var targetInst = il[pos];

                int pattern = rng.Next(0, 9);
                var seq = new List<Instruction>();
                switch (pattern)
                {
                    case 0:
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(int.MinValue, int.MaxValue)));
                        seq.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    case 1:
                        seq.Add(Instruction.Create(DnOpCodes.Nop));
                        break;
                    case 2:
                    {
                        int a = rng.Next(100, 99999);
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                        seq.Add(Instruction.Create(DnOpCodes.Xor));
                        seq.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                    case 3:
                    {

                        seq.Add(Instruction.Create(DnOpCodes.Br, targetInst));

                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        seq.Add(Instruction.Create(DnOpCodes.Xor));
                        seq.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                    case 4:
                    {

                        int v = rng.Next(1, int.MaxValue);
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, v));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, v));
                        seq.Add(Instruction.Create(DnOpCodes.Ceq));
                        seq.Add(Instruction.Create(DnOpCodes.Brtrue, targetInst));

                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        seq.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                    case 5:
                    {

                        int v = rng.Next(1, int.MaxValue);
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, v));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, v));
                        seq.Add(Instruction.Create(DnOpCodes.Xor));
                        seq.Add(Instruction.Create(DnOpCodes.Brfalse, targetInst));
                        seq.Add(Instruction.Create(DnOpCodes.Nop));
                        break;
                    }
                    case 6:
                    {

                        int x = rng.Next();
                        int y = rng.Next();
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, y));
                        seq.Add(Instruction.Create(DnOpCodes.Or));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, y));
                        seq.Add(Instruction.Create(DnOpCodes.And));
                        seq.Add(Instruction.Create(DnOpCodes.Sub));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, y));
                        seq.Add(Instruction.Create(DnOpCodes.Xor));
                        seq.Add(Instruction.Create(DnOpCodes.Sub));
                        seq.Add(Instruction.Create(DnOpCodes.Brfalse, targetInst));

                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        seq.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                    case 7:
                    {

                        int v = rng.Next();
                        seq.Add(Instruction.Create(DnOpCodes.Ldc_I4, v));
                        seq.Add(Instruction.Create(DnOpCodes.Dup));
                        seq.Add(Instruction.Create(DnOpCodes.Not));
                        seq.Add(Instruction.Create(DnOpCodes.Xor));
                        seq.Add(Instruction.Create(DnOpCodes.Pop));
                        break;
                    }
                    default:
                        seq.Add(Instruction.Create(DnOpCodes.Nop));
                        seq.Add(Instruction.Create(DnOpCodes.Nop));
                        break;
                }

                for (int i = seq.Count - 1; i >= 0; i--)
                    il.Insert(pos, seq[i]);

                for (int i = 0; i < safe.Count; i++)
                    if (safe[i] >= pos) safe[i] += seq.Count;
            }
        }
    }
}

