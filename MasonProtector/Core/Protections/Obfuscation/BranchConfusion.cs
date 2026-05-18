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
    internal class BranchConfusionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private List<TypeDef> hostTypes;

        internal BranchConfusionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyBranchConfusion(ModuleDef module, TypeDef modType)
        {
            hostTypes = new List<TypeDef>();

            CreateBranchHostTypes(module);
            PopulateHostsWithFields(module);
            PopulateHostsWithMethods(module);
            InjectExtraDecoyMethods(module);
        }

        private void CreateBranchHostTypes(ModuleDef module)
        {
            int hostCount = rng.Next(16, 28);
            for (int i = 0; i < hostCount; i++)
            {
                var host = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(host);
                engine.injectedTypes.Add(host);
                hostTypes.Add(host);
            }
        }

        private void PopulateHostsWithFields(ModuleDef module)
        {
            foreach (TypeDef host in hostTypes)
            {
                int fieldCount = rng.Next(10, 22);
                for (int f = 0; f < fieldCount; f++)
                {
                    TypeSig fieldType;
                    int t = rng.Next(0, 6);
                    if (t == 0) fieldType = module.CorLibTypes.Int32;
                    else if (t == 1) fieldType = module.CorLibTypes.Int64;
                    else if (t == 2) fieldType = module.CorLibTypes.Boolean;
                    else if (t == 3) fieldType = module.CorLibTypes.Byte;
                    else if (t == 4) fieldType = module.CorLibTypes.Double;
                    else fieldType = new SZArraySig(module.CorLibTypes.Int32);

                    host.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(fieldType),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }
            }
        }

        private void PopulateHostsWithMethods(ModuleDef module)
        {
            foreach (TypeDef host in hostTypes)
            {
                int methodCount = rng.Next(3, 7);
                for (int m = 0; m < methodCount; m++)
                {
                    MethodDef method;
                    int kind = rng.Next(0, 4);
                    if (kind == 0)
                        method = BuildSwitchMethod(module);
                    else if (kind == 1)
                        method = BuildNestedTryCatch(module);
                    else if (kind == 2)
                        method = BuildLoopMethod(module);
                    else
                        method = BuildBranchyMethod(module);

                    host.Methods.Add(method);
                    engine.injectedMethods.Add(method);
                }
            }
        }

        private void InjectExtraDecoyMethods(ModuleDef module)
        {
            int extraCount = rng.Next(8, 16);
            for (int i = 0; i < extraCount; i++)
            {
                TypeDef host = hostTypes[rng.Next(hostTypes.Count)];
                MethodDef method;
                int kind = rng.Next(0, 4);
                if (kind == 0)
                    method = BuildSwitchMethod(module);
                else if (kind == 1)
                    method = BuildNestedTryCatch(module);
                else if (kind == 2)
                    method = BuildLoopMethod(module);
                else
                    method = BuildBranchyMethod(module);

                host.Methods.Add(method);
                engine.injectedMethods.Add(method);
            }
        }

        private MethodDef BuildSwitchMethod(ModuleDef module)
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
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var retLabel = Instruction.Create(DnOpCodes.Ldloc_0);

            int caseCount = rng.Next(4, 8);
            var caseTargets = new Instruction[caseCount];
            for (int c = 0; c < caseCount; c++)
            {
                caseTargets[c] = Instruction.Create(DnOpCodes.Nop);
            }

            var defaultTarget = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, caseCount));
            il.Add(Instruction.Create(DnOpCodes.Rem));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Switch, caseTargets));
            il.Add(Instruction.Create(DnOpCodes.Br, defaultTarget));

            for (int c = 0; c < caseCount; c++)
            {
                il.Add(caseTargets[c]);
                int ops = rng.Next(3, 7);
                for (int r = 0; r < ops; r++)
                {
                    EmitRandomALU(il, rng);
                }
                il.Add(Instruction.Create(DnOpCodes.Br, retLabel));
            }

            il.Add(defaultTarget);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildNestedTryCatch(ModuleDef module)
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
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            var afterAll = Instruction.Create(DnOpCodes.Ldloc_0);

            var outerTryStart = Instruction.Create(DnOpCodes.Ldarg_0);
            var innerTryStart = Instruction.Create(DnOpCodes.Ldloc_0);
            var innerHandlerStart = Instruction.Create(DnOpCodes.Pop);
            var innerAfter = Instruction.Create(DnOpCodes.Nop);
            var outerHandlerStart = Instruction.Create(DnOpCodes.Pop);

            il.Add(outerTryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(innerTryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            for (int r = 0; r < rng.Next(3, 6); r++)
            {
                int op = rng.Next(0, 4);
                if (op == 0)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                }
                else if (op == 1)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_1));
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
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                    il.Add(Instruction.Create(DnOpCodes.Shr));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Leave, innerAfter));

            il.Add(innerHandlerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Leave, innerAfter));

            il.Add(innerAfter);

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int r = 0; r < rng.Next(2, 5); r++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                il.Add(Instruction.Create(DnOpCodes.Xor));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }

            il.Add(Instruction.Create(DnOpCodes.Leave, afterAll));

            il.Add(outerHandlerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterAll));

            var outerHandlerEnd = Instruction.Create(DnOpCodes.Nop);
            il.Add(outerHandlerEnd);

            il.Add(afterAll);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            var innerHandler = new ExceptionHandler(ExceptionHandlerType.Catch);
            innerHandler.TryStart = innerTryStart;
            innerHandler.TryEnd = innerHandlerStart;
            innerHandler.HandlerStart = innerHandlerStart;
            innerHandler.HandlerEnd = innerAfter;
            innerHandler.CatchType = module.CorLibTypes.GetTypeRef("System", "Exception");
            method.Body.ExceptionHandlers.Add(innerHandler);

            var outerHandler = new ExceptionHandler(ExceptionHandlerType.Catch);
            outerHandler.TryStart = outerTryStart;
            outerHandler.TryEnd = outerHandlerStart;
            outerHandler.HandlerStart = outerHandlerStart;
            outerHandler.HandlerEnd = outerHandlerEnd;
            outerHandler.CatchType = module.CorLibTypes.GetTypeRef("System", "Exception");
            method.Body.ExceptionHandlers.Add(outerHandler);

            return method;
        }

        private MethodDef BuildLoopMethod(ModuleDef module)
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
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            int loopBound = rng.Next(4, 12);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            var loopCheck = Instruction.Create(DnOpCodes.Ldloc_2);
            var loopBody = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Br, loopCheck));

            il.Add(loopBody);

            for (int r = 0; r < rng.Next(4, 8); r++)
            {
                int op = rng.Next(0, 6);
                if (op == 0)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_3));
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
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                }
                else if (op == 3)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Or));
                    il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[4]));
                }
                else if (op == 4)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 8)));
                    il.Add(Instruction.Create(DnOpCodes.Shl));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                }
                else
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                }
            }

            var innerLoopCheck = Instruction.Create(DnOpCodes.Ldloc_3);
            var innerLoopBody = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));
            il.Add(Instruction.Create(DnOpCodes.Br, innerLoopCheck));

            il.Add(innerLoopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            il.Add(innerLoopCheck);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(2, 6)));
            il.Add(Instruction.Create(DnOpCodes.Blt, innerLoopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(loopCheck);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, loopBound));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildBranchyMethod(ModuleDef module)
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
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var retLabel = Instruction.Create(DnOpCodes.Ldloc_0);

            int branchCount = rng.Next(4, 8);
            for (int b = 0; b < branchCount; b++)
            {
                var elseLabel = Instruction.Create(DnOpCodes.Nop);
                var mergeLabel = Instruction.Create(DnOpCodes.Nop);

                int condKind = rng.Next(0, 4);
                if (condKind == 0)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Brfalse, elseLabel));
                }
                else if (condKind == 1)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Bgt, elseLabel));
                }
                else if (condKind == 2)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Brtrue, elseLabel));
                }
                else
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                    il.Add(Instruction.Create(DnOpCodes.Shr));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Beq, elseLabel));
                }

                int thenOps = rng.Next(2, 5);
                for (int t = 0; t < thenOps; t++)
                {
                    EmitRandomALU(il, rng);
                }
                il.Add(Instruction.Create(DnOpCodes.Br, mergeLabel));

                il.Add(elseLabel);
                int elseOps = rng.Next(2, 5);
                for (int e = 0; e < elseOps; e++)
                {
                    EmitRandomALU(il, rng);
                }

                il.Add(mergeLabel);
            }

            var tryStart = Instruction.Create(DnOpCodes.Ldloc_0);
            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            var handlerEnd = Instruction.Create(DnOpCodes.Nop);

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, retLabel));

            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, retLabel));
            il.Add(handlerEnd);

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            var exHandler = new ExceptionHandler(ExceptionHandlerType.Catch);
            exHandler.TryStart = tryStart;
            exHandler.TryEnd = handlerStart;
            exHandler.HandlerStart = handlerStart;
            exHandler.HandlerEnd = handlerEnd;
            exHandler.CatchType = module.CorLibTypes.GetTypeRef("System", "Exception");
            method.Body.ExceptionHandlers.Add(exHandler);

            return method;
        }

        private void EmitRandomALU(IList<Instruction> il, Random r)
        {
            int op = r.Next(0, 10);
            if (op == 0)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r.Next()));
                il.Add(Instruction.Create(DnOpCodes.Xor));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }
            else if (op == 1)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Not));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }
            else if (op == 2)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r.Next()));
                il.Add(Instruction.Create(DnOpCodes.Add));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }
            else if (op == 3)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r.Next()));
                il.Add(Instruction.Create(DnOpCodes.Sub));
                il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            }
            else if (op == 4)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r.Next(1, 16)));
                il.Add(Instruction.Create(DnOpCodes.Shl));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }
            else if (op == 5)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r.Next(1, 16)));
                il.Add(Instruction.Create(DnOpCodes.Shr));
                il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            }
            else if (op == 6)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                il.Add(Instruction.Create(DnOpCodes.And));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }
            else if (op == 7)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                il.Add(Instruction.Create(DnOpCodes.Or));
                il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            }
            else if (op == 8)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                il.Add(Instruction.Create(DnOpCodes.Not));
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.And));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }
            else
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r.Next()));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            }
        }
    }
}

