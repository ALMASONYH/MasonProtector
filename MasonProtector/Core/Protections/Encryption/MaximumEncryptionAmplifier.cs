using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{

    internal class MaximumEncryptionAmplifierProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal MaximumEncryptionAmplifierProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyMaximumAmplifier(ModuleDef module)
        {
            if (engine.cfg == null || !engine.cfg.MaximumEncryption) return;

            const int MaxBodyForFullAmplify   = 600;
            const int MaxBodyForReducedAmplify = 2500;

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (method == null) continue;
                    if (!method.HasBody) continue;
                    if (!method.Body.HasInstructions) continue;
                    if (engine.IsMethodUserExcluded(method)) continue;
                    if (method.HasGenericParameters) continue;
                    if (method.IsPinvokeImpl) continue;
                    if (method.Name.StartsWith("<")) continue;
                    if (method.IsRuntimeSpecialName && !method.IsStaticConstructor) continue;

                    if (method.Name == "InitializeComponent" &&
                        method.DeclaringType != null &&
                        engine.IsWinFormsType(method.DeclaringType))
                        continue;
                    if (method.Name == "Dispose" &&
                        method.MethodSig != null &&
                        method.MethodSig.Params.Count == 1 &&
                        method.MethodSig.Params[0].FullName == "System.Boolean" &&
                        method.DeclaringType != null &&
                        engine.IsWinFormsType(method.DeclaringType))
                        continue;

                    int bodySize = method.Body.Instructions.Count;

                    if (bodySize > MaxBodyForReducedAmplify) continue;

                    bool reduced = bodySize > MaxBodyForFullAmplify;
                    try
                    {
                        AmplifyIntLoads(module, method, reduced);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch {  }
                }
            }
        }

        private void AmplifyIntLoads(ModuleDef module, MethodDef method, bool reduced)
        {
            var il = method.Body.Instructions;

            int skipMod = reduced ? 4 : 3;
            for (int i = 0; i < il.Count; i++)
            {
                if (!engine.IsIntLoad(il[i])) continue;
                int val = engine.ExtractInt(il[i]);
                if (val == int.MinValue) continue;

                if (i + 1 < il.Count)
                {
                    var next = il[i + 1];
                    if (next.OpCode == DnOpCodes.Switch) continue;
                }

                if (rng.Next(0, skipMod) == 0) continue;

                var chain = BuildExtremeChain(val, reduced);
                if (chain == null || chain.Count == 0) continue;

                il[i].OpCode = chain[0].OpCode;
                il[i].Operand = chain[0].Operand;
                for (int j = 1; j < chain.Count; j++)
                    il.Insert(i + j, chain[j]);
                i += chain.Count - 1;
            }
        }

        private List<Instruction> BuildExtremeChain(int target, bool reduced)
        {

            int depth = reduced ? rng.Next(3, 6) : rng.Next(7, 13);
            int[] modes = new int[depth];
            int[] keys  = new int[depth];
            for (int d = 0; d < depth; d++)
            {
                modes[d] = rng.Next(0, 5);
                keys[d]  = rng.Next(int.MinValue, int.MaxValue);
            }

            int startValue = target;
            for (int i = depth - 1; i >= 0; i--)
            {
                switch (modes[i])
                {
                    case 0:
                        startValue = startValue ^ keys[i];
                        break;
                    case 1:
                        startValue = unchecked(startValue - keys[i]);
                        break;
                    case 2:
                        startValue = unchecked(startValue + keys[i]);
                        break;
                    case 3:
                        startValue = ~startValue;
                        break;
                    default:
                        startValue = ~startValue;
                        startValue = startValue ^ keys[i];
                        break;
                }
            }

            var result = new List<Instruction>();
            result.Add(Instruction.Create(DnOpCodes.Ldc_I4, startValue));

            for (int i = 0; i < depth; i++)
            {
                switch (modes[i])
                {
                    case 0:
                        result.Add(Instruction.Create(DnOpCodes.Ldc_I4, keys[i]));
                        result.Add(Instruction.Create(DnOpCodes.Xor));
                        break;
                    case 1:
                        result.Add(Instruction.Create(DnOpCodes.Ldc_I4, keys[i]));
                        result.Add(Instruction.Create(DnOpCodes.Add));
                        break;
                    case 2:
                        result.Add(Instruction.Create(DnOpCodes.Ldc_I4, keys[i]));
                        result.Add(Instruction.Create(DnOpCodes.Sub));
                        break;
                    case 3:
                        result.Add(Instruction.Create(DnOpCodes.Not));
                        break;
                    default:
                        result.Add(Instruction.Create(DnOpCodes.Ldc_I4, keys[i]));
                        result.Add(Instruction.Create(DnOpCodes.Xor));
                        result.Add(Instruction.Create(DnOpCodes.Not));
                        break;
                }
            }

            return result;
        }
    }
}
