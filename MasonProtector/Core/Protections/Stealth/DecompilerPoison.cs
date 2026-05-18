using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{

    internal class DecompilerPoisonProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int TRAP_TYPE_COUNT = 160;
        private const int TRAPS_PER_TYPE = 16;

        internal DecompilerPoisonProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyDecompilerPoison(ModuleDef module)
        {
            for (int t = 0; t < TRAP_TYPE_COUNT; t++)
            {
                var hostType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                hostType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(hostType);
                engine.injectedTypes.Add(hostType);

                int fieldCount = rng.Next(4, 10);
                for (int f = 0; f < fieldCount; f++)
                {
                    TypeSig ft;
                    int kind = rng.Next(0, 5);
                    if (kind == 0) ft = module.CorLibTypes.Int32;
                    else if (kind == 1) ft = module.CorLibTypes.Int64;
                    else if (kind == 2) ft = module.CorLibTypes.Boolean;
                    else if (kind == 3) ft = new SZArraySig(module.CorLibTypes.Int32);
                    else ft = module.CorLibTypes.Double;

                    hostType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < TRAPS_PER_TYPE; m++)
                {
                    MethodDef trap = BuildTrapMethod(module);
                    hostType.Methods.Add(trap);
                    engine.injectedMethods.Add(trap);
                }
            }
        }

        private MethodDef BuildTrapMethod(ModuleDef module)
        {

            int sigKind = rng.Next(0, 4);
            MethodSig sig;
            switch (sigKind)
            {
                case 0:
                    sig = MethodSig.CreateStatic(module.CorLibTypes.Int32,
                        module.CorLibTypes.Int32, module.CorLibTypes.Boolean);
                    break;
                case 1:
                    sig = MethodSig.CreateStatic(module.CorLibTypes.Int32,
                        module.CorLibTypes.Int32);
                    break;
                case 2:
                    sig = MethodSig.CreateStatic(module.CorLibTypes.Int32,
                        module.CorLibTypes.Int32, module.CorLibTypes.Int32);
                    break;
                default:
                    sig = MethodSig.CreateStatic(module.CorLibTypes.Int32,
                        module.CorLibTypes.Object);
                    break;
            }

            var method = new MethodDefUser(engine.MakeName(), sig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

            var il = method.Body.Instructions;
            int pattern = rng.Next(0, 4);
            switch (pattern)
            {
                case 0: EmitTrapPattern_BranchingUnderflow(il, method); break;
                case 1: EmitTrapPattern_SwitchUnderflow(il, method);    break;
                case 2: EmitTrapPattern_CatchUnderflow(il, method, module); break;
                default: EmitTrapPattern_LoopUnderflow(il, method);     break;
            }

            method.Body.KeepOldMaxStack = false;
            method.Body.MaxStack = 8;
            return method;
        }

        private void EmitTrapPattern_BranchingUnderflow(IList<Instruction> il, MethodDef m)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 1000)));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var branchB = Instruction.Create(DnOpCodes.Ldloc_1);
            var afterMerge = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Bgt, branchB));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Br, afterMerge));

            il.Add(branchB);
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Br, afterMerge));

            il.Add(afterMerge);
            il.Add(Instruction.Create(DnOpCodes.Ret));
        }

        private void EmitTrapPattern_SwitchUnderflow(IList<Instruction> il, MethodDef m)
        {
            var c0 = Instruction.Create(DnOpCodes.Ldloc_0);
            var c1 = Instruction.Create(DnOpCodes.Add);
            var c2 = Instruction.Create(DnOpCodes.Xor);
            var ret = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_3));
            il.Add(Instruction.Create(DnOpCodes.Rem));
            il.Add(Instruction.Create(DnOpCodes.Switch, new Instruction[] { c0, c1, c2 }));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(ret);

            il.Add(c0);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(ret);

            il.Add(c1);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(ret);

            il.Add(c2);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(ret);
        }

        private void EmitTrapPattern_CatchUnderflow(IList<Instruction> il, MethodDef m, ModuleDef module)
        {
            var tryStart = Instruction.Create(DnOpCodes.Ldarg_0);
            var leaveOut = Instruction.Create(DnOpCodes.Leave, (Instruction)null);
            var handlerStart = Instruction.Create(DnOpCodes.Add);
            var afterCatch = Instruction.Create(DnOpCodes.Ldc_I4_0);
            var ret = Instruction.Create(DnOpCodes.Ret);

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            leaveOut.Operand = afterCatch;
            il.Add(leaveOut);

            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Pop));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

            il.Add(afterCatch);
            il.Add(ret);

            m.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = afterCatch,

                CatchType = new TypeRefUser(module, "System", "Exception",
                    module.CorLibTypes.AssemblyRef),
            });
        }

        private void EmitTrapPattern_LoopUnderflow(IList<Instruction> il, MethodDef m)
        {
            var loopHead = Instruction.Create(DnOpCodes.Ldloc_2);
            var afterLoop = Instruction.Create(DnOpCodes.Ldloc_0);
            var body = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Br, loopHead));

            il.Add(body);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Mul));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(loopHead);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(3, 10)));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Blt, body));

            il.Add(afterLoop);
            il.Add(Instruction.Create(DnOpCodes.Ret));
        }
    }
}

