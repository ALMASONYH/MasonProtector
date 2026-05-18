using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class MutationIndirectionProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int CALLER_VARIANTS = 6;

        private const double WRAP_PROBABILITY = 0.25;

        private const int MIN_INTERESTING_CONST = 8;

        private List<MethodDef> intCallers;

        internal MutationIndirectionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal int ApplyMutationIndirection(ModuleDef module)
        {
            BuildCallerPool(module);
            int wrapped = 0;
            foreach (TypeDef t in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(t)) continue;
                if (engine.injectedTypes.Contains(t)) continue;
                if (engine.IsWinFormsType(t)) continue;
                foreach (MethodDef m in t.Methods)
                {
                    if (!engine.CanProcessMethod(m)) continue;
                    if (m.Name == "InitializeComponent") continue;
                    if (engine.injectedMethods.Contains(m)) continue;
                    try { wrapped += WrapConstantsIn(m); }
                    catch { }
                }
            }
            return wrapped;
        }

        private void BuildCallerPool(ModuleDef module)
        {
            intCallers = new List<MethodDef>();
            for (int i = 0; i < CALLER_VARIANTS; i++)
            {
                TypeDef host = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                                  DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(host);
                engine.injectedTypes.Add(host);

                MethodDef key = new MethodDefUser(engine.MakeName(),
                    MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig);
                key.Body = new CilBody();
                key.Body.InitLocals = true;

                key.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                key.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                host.Methods.Add(key);
                engine.injectedMethods.Add(key);
                intCallers.Add(key);
            }
        }

        private int WrapConstantsIn(MethodDef m)
        {
            if (m.Body == null) return 0;
            var il = m.Body.Instructions;
            int wrapped = 0;

            for (int i = 0; i < il.Count; i++)
            {
                Instruction ins = il[i];
                if (ins.OpCode != OpCodes.Ldc_I4) continue;
                if (!(ins.Operand is int)) continue;
                int v = (int)ins.Operand;

                if (Math.Abs(v) < MIN_INTERESTING_CONST) continue;
                if (rng.NextDouble() > WRAP_PROBABILITY) continue;

                MethodDef caller = intCallers[rng.Next(intCallers.Count)];

                il.Insert(i + 1, Instruction.Create(DnOpCodes.Call, caller));
                wrapped++;
                i++;
            }
            return wrapped;
        }
    }
}

