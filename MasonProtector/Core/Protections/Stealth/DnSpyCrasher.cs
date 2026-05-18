using System;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class DnSpyCrasherProtection
    {
        private readonly Obfuscation engine;
        private readonly Random rng;

        internal DnSpyCrasherProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyDnSpyCrasher(ModuleDef module)
        {
            var crashType = new TypeDefUser("", BuildHostileName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            crashType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(crashType);
            engine.injectedTypes.Add(crashType);

            BuildBigSwitchTrap(module, crashType);
            BuildLeaveChainTrap(module, crashType);
            BuildNopFloodTrap(module, crashType);
        }

        private string BuildHostileName()
        {

            var sb = new StringBuilder();
            sb.Append('\u202E');
            sb.Append(engine.MakeName(8));
            sb.Append('\u200C');
            sb.Append(engine.MakeName(4));
            sb.Append('\u200D');
            return sb.ToString();
        }

        private void BuildBigSwitchTrap(ModuleDef module, TypeDef owner)
        {
            var m = new MethodDefUser(BuildHostileName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            var il = m.Body.Instructions;

            var ret = Instruction.Create(DnOpCodes.Ret);

            int N = rng.Next(4500, 8500);
            var targets = new Instruction[N];
            for (int i = 0; i < N; i++) targets[i] = ret;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(new Instruction(DnOpCodes.Switch, targets));
            il.Add(ret);

            owner.Methods.Add(m);
            engine.injectedMethods.Add(m);
        }

        private void BuildLeaveChainTrap(ModuleDef module, TypeDef owner)
        {
            var m = new MethodDefUser(BuildHostileName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            var il = m.Body.Instructions;

            var ret = Instruction.Create(DnOpCodes.Ret);

            int chainLen = rng.Next(24, 48);
            var tryStarts = new Instruction[chainLen];
            var leaves = new Instruction[chainLen];
            var handlerStarts = new Instruction[chainLen];

            for (int i = 0; i < chainLen; i++)
            {
                tryStarts[i] = Instruction.Create(DnOpCodes.Nop);
                leaves[i] = Instruction.Create(DnOpCodes.Leave, ret);
                handlerStarts[i] = Instruction.Create(DnOpCodes.Pop);
            }

            for (int i = 0; i < chainLen; i++)
            {
                il.Add(tryStarts[i]);
                il.Add(leaves[i]);
                il.Add(handlerStarts[i]);
                il.Add(Instruction.Create(DnOpCodes.Leave, ret));
                m.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                {
                    TryStart = tryStarts[i],
                    TryEnd = handlerStarts[i],
                    HandlerStart = handlerStarts[i],
                    HandlerEnd = i + 1 < chainLen ? tryStarts[i + 1] : ret,

                    CatchType = new TypeRefUser(module, "System", "Exception",
                        module.CorLibTypes.AssemblyRef),
                });
            }
            il.Add(ret);

            owner.Methods.Add(m);
            engine.injectedMethods.Add(m);
        }

        private void BuildNopFloodTrap(ModuleDef module, TypeDef owner)
        {
            var m = new MethodDefUser(BuildHostileName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            var il = m.Body.Instructions;

            int n = rng.Next(2500, 6000);
            for (int i = 0; i < n; i++) il.Add(Instruction.Create(DnOpCodes.Nop));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            owner.Methods.Add(m);
            engine.injectedMethods.Add(m);
        }
    }
}

