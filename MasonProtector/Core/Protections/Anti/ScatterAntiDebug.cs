using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class ScatterAntiDebugProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal ScatterAntiDebugProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ScatterAntiDebugChecks(ModuleDef module, TypeDef modType)
        {
            NativeShroud shroud = engine.antiShroud;
            if (shroud == null) return;

            int injected = 0;
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (rng.Next(0, 2) != 0) continue;
                    if (injected >= 240) return;

                    var il = method.Body.Instructions;
                    int pos = rng.Next(0, Math.Max(1, il.Count - 2));

                    if (il[pos].OpCode == DnOpCodes.Ret) continue;
                    if (il[pos].OpCode == DnOpCodes.Leave) continue;
                    if (il[pos].OpCode == DnOpCodes.Leave_S) continue;
                    if (il[pos].OpCode == DnOpCodes.Rethrow) continue;

                    if (method.Body.HasExceptionHandlers)
                    {
                        bool isBoundary = false;
                        foreach (var eh in method.Body.ExceptionHandlers)
                        {
                            if (il[pos] == eh.HandlerStart || il[pos] == eh.HandlerEnd ||
                                il[pos] == eh.TryStart    || il[pos] == eh.TryEnd     ||
                                il[pos] == eh.FilterStart)
                            {
                                isBoundary = true;
                                break;
                            }
                        }
                        if (isBoundary) continue;
                    }

                    var skip = il[pos];

                    int detectVariant = rng.Next(3);
                    int killVariant = rng.Next(4);

                    int killPos;
                    if (detectVariant == 0)
                    {
                        il.Insert(pos,     Instruction.Create(DnOpCodes.Call, shroud.IsDebuggerPresent));
                        il.Insert(pos + 1, Instruction.Create(DnOpCodes.Brfalse, skip));
                        killPos = pos + 2;
                    }
                    else if (detectVariant == 1)
                    {
                        il.Insert(pos,     Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
                        il.Insert(pos + 1, Instruction.Create(DnOpCodes.Ldc_I4, 0x1F0FFF));
                        il.Insert(pos + 2, Instruction.Create(DnOpCodes.Pop));
                        il.Insert(pos + 3, Instruction.Create(DnOpCodes.Pop));
                        il.Insert(pos + 4, Instruction.Create(DnOpCodes.Call, shroud.IsDebuggerPresent));
                        il.Insert(pos + 5, Instruction.Create(DnOpCodes.Brfalse, skip));
                        killPos = pos + 6;
                    }
                    else
                    {
                        il.Insert(pos,     Instruction.Create(DnOpCodes.Call, shroud.GetTickCount));
                        il.Insert(pos + 1, Instruction.Create(DnOpCodes.Pop));
                        il.Insert(pos + 2, Instruction.Create(DnOpCodes.Call, shroud.IsDebuggerPresent));
                        il.Insert(pos + 3, Instruction.Create(DnOpCodes.Brfalse, skip));
                        killPos = pos + 4;
                    }

                    switch (killVariant)
                    {
                        case 0:
                            il.Insert(killPos,     Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
                            il.Insert(killPos + 1, Instruction.Create(DnOpCodes.Ldc_I4_M1));
                            il.Insert(killPos + 2, Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
                            il.Insert(killPos + 3, Instruction.Create(DnOpCodes.Pop));
                            break;
                        case 1:
                            il.Insert(killPos,     Instruction.Create(DnOpCodes.Ldc_I4_M1));
                            il.Insert(killPos + 1, Instruction.Create(DnOpCodes.Call, shroud.ExitProcess));
                            break;
                        case 2:
                            il.Insert(killPos,     Instruction.Create(DnOpCodes.Ldc_I4, -6));
                            il.Insert(killPos + 1, Instruction.Create(DnOpCodes.Call, shroud.ExitProcess));
                            break;
                        case 3:
                            il.Insert(killPos,     Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
                            il.Insert(killPos + 1, Instruction.Create(DnOpCodes.Ldc_I4, -7));
                            il.Insert(killPos + 2, Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
                            il.Insert(killPos + 3, Instruction.Create(DnOpCodes.Pop));
                            break;
                    }
                    injected++;
                }
            }
        }
    }
}

