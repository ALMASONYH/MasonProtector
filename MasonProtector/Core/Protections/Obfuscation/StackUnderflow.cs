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
    internal class StackUnderflowProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal StackUnderflowProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyStackUnderflow(ModuleDef module, TypeDef modType)
        {
            InjectTryCatchWrappers(module);
            InjectFakeLocalVarNoise(module);
            InjectDecoyTypes(module);
        }

        private void InjectDecoyTypes(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(10, 20); i++)
            {
                var decoyType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                decoyType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(decoyType);
                engine.injectedTypes.Add(decoyType);

                for (int f = 0; f < rng.Next(8, 18); f++)
                {
                    decoyType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(5, 14); m++)
                {
                    var decoyMethod = BuildTryCatchMethod(module, decoyType);
                    decoyType.Methods.Add(decoyMethod);
                    engine.injectedMethods.Add(decoyMethod);
                }
            }
        }

        private void InjectTryCatchWrappers(ModuleDef module)
        {
            var wrapperType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            wrapperType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed;
            module.Types.Add(wrapperType);
            engine.injectedTypes.Add(wrapperType);

            for (int i = 0; i < rng.Next(12, 26); i++)
            {
                var wrapMethod = BuildTryCatchMethod(module, wrapperType);
                wrapperType.Methods.Add(wrapMethod);
                engine.injectedMethods.Add(wrapMethod);
            }

            for (int f = 0; f < rng.Next(6, 14); f++)
            {
                wrapperType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private MethodDef BuildTryCatchMethod(ModuleDef module, TypeDef host)
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
            var tryEnd = Instruction.Create(DnOpCodes.Nop);
            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            var handlerEnd = Instruction.Create(DnOpCodes.Nop);
            var afterHandler = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int n = 0; n < rng.Next(3, 8); n++)
            {
                int op = rng.Next(0, 4);
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
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Leave, afterHandler));
            il.Add(tryEnd);

            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterHandler));
            il.Add(handlerEnd);

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

        private void InjectFakeLocalVarNoise(ModuleDef module)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (method.IsConstructor || method.IsStaticConstructor) continue;
                    if (rng.Next(0, 3) != 0) continue;
                    try
                    {
                        AddFakeLocals(module, method);
                    }
                    catch { }
                }
            }
        }

        private void AddFakeLocals(ModuleDef module, MethodDef method)
        {
            int fakeCount = rng.Next(1, 4);
            var fakeLocals = new List<Local>();

            for (int i = 0; i < fakeCount; i++)
            {
                TypeSig localType;
                int t = rng.Next(0, 4);
                switch (t)
                {
                    case 0: localType = module.CorLibTypes.Int32; break;
                    case 1: localType = module.CorLibTypes.Int64; break;
                    case 2: localType = module.CorLibTypes.Boolean; break;
                    default: localType = module.CorLibTypes.Byte; break;
                }
                var local = new Local(localType);
                method.Body.Variables.Add(local);
                fakeLocals.Add(local);
            }

            var il = method.Body.Instructions;
            if (il.Count < 2) return;

            var safe = engine.FindSafeInsertPositions(il, method.Body.ExceptionHandlers);
            if (safe.Count == 0) return;

            foreach (var local in fakeLocals)
            {
                int insertPos = safe[rng.Next(0, safe.Count)];

                int idx = insertPos;
                il.Insert(idx++, engine.LoadInt(rng.Next(-100, 100)));
                var et = local.Type.RemovePinnedAndModifiers().ElementType;
                if (et == ElementType.I8 || et == ElementType.U8)
                    il.Insert(idx++, Instruction.Create(DnOpCodes.Conv_I8));
                else if (et == ElementType.R4)
                    il.Insert(idx++, Instruction.Create(DnOpCodes.Conv_R4));
                else if (et == ElementType.R8)
                    il.Insert(idx++, Instruction.Create(DnOpCodes.Conv_R8));
                il.Insert(idx, Instruction.Create(DnOpCodes.Stloc, local));

                safe = engine.FindSafeInsertPositions(il, method.Body.ExceptionHandlers);
                if (safe.Count == 0) return;
            }
        }
    }
}

