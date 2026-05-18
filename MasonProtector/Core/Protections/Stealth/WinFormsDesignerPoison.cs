using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class WinFormsDesignerPoisonProtection
    {
        private Obfuscation engine;

        internal WinFormsDesignerPoisonProtection(Obfuscation eng)
        {
            engine = eng;
        }

        internal int ApplyWinFormsDesignerPoison(ModuleDef module)
        {
            int poisoned = 0;
            foreach (TypeDef t in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(t)) continue;
                if (!engine.IsWinFormsType(t)) continue;

                if (engine.IsTypeUserExcluded(t)) continue;

                foreach (MethodDef m in t.Methods)
                {
                    if (m == null) continue;
                    if (!m.HasBody) continue;
                    if (engine.injectedMethods.Contains(m)) continue;
                    if (engine.IsMethodUserExcluded(m)) continue;

                    bool target = false;

                    if (m.Name == "InitializeComponent") target = true;

                    if (!target && m.Name == "Dispose" && m.MethodSig != null &&
                        m.MethodSig.Params.Count == 1 &&
                        m.MethodSig.Params[0].FullName == "System.Boolean")
                        target = true;

                    if (!target) continue;

                    if (IsAlreadyPoisoned(m)) continue;

                    if (m.Body.HasExceptionHandlers && m.Body.ExceptionHandlers.Count > 0)
                        continue;

                    try
                    {
                        ApplyPoisonPrologue(m, module);
                        poisoned++;
                    }
                    catch {  }
                }
            }
            return poisoned;
        }

        private bool IsAlreadyPoisoned(MethodDef m)
        {

            var il = m.Body.Instructions;
            if (il.Count < 6) return false;
            return il[0].OpCode.Code == Code.Br_S &&
                   il[1].OpCode.Code == Code.Nop &&
                   il[2].OpCode.Code == Code.Leave_S &&
                   il[3].OpCode.Code == Code.Add &&
                   il[4].OpCode.Code == Code.Pop &&
                   il[5].OpCode.Code == Code.Leave_S;
        }

        private void ApplyPoisonPrologue(MethodDef m, ModuleDef module)
        {
            var body = m.Body;
            var il = body.Instructions;
            if (il.Count == 0) return;

            Instruction realStart = il[0];
            Instruction deadTry    = Instruction.Create(DnOpCodes.Nop);
            Instruction deadCatch  = Instruction.Create(DnOpCodes.Add);

            il.Insert(0, Instruction.Create(DnOpCodes.Br_S, realStart));
            il.Insert(1, deadTry);
            il.Insert(2, Instruction.Create(DnOpCodes.Leave_S, realStart));
            il.Insert(3, deadCatch);
            il.Insert(4, Instruction.Create(DnOpCodes.Pop));
            il.Insert(5, Instruction.Create(DnOpCodes.Leave_S, realStart));

            body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart     = deadTry,
                TryEnd       = deadCatch,
                HandlerStart = deadCatch,
                HandlerEnd   = realStart,

                CatchType    = new TypeRefUser(module, "System", "Exception",
                    module.CorLibTypes.AssemblyRef)
            });

            body.KeepOldMaxStack = true;
        }
    }
}

