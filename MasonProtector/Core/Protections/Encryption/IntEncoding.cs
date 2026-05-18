using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class IntEncodingProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal IntEncodingProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyIntEncoding(ModuleDef module)
        {

            bool maxEnc = engine.cfg != null && engine.cfg.MaximumEncryption;
            int passes = maxEnc ? 2 : 1;
            for (int pass = 0; pass < passes; pass++)
            {
                foreach (TypeDef type in module.GetTypes())
                {
                    if (engine.IsCompilerGenerated(type)) continue;
                    foreach (MethodDef method in type.Methods)
                    {
                        if (!engine.CanProcessMethod(method)) continue;
                        try
                        {
                            EncodeMethodInts(module, method, maxEnc);
                            method.Body.SimplifyBranches();
                            method.Body.OptimizeBranches();
                        }
                        catch { }
                    }
                }
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsCompilerGenerated(type)) continue;
                if (!engine.IsWinFormsType(type)) continue;

                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (method.HasGenericParameters) continue;
                    if (engine.IsMethodUserExcluded(method)) continue;
                    try
                    {
                        bool aggressive = method.Name == "InitializeComponent"
                            || engine.designerSplitSubMethods.Contains(method);
                        EncodeMethodInts(module, method, aggressive);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }
        }

        private void EncodeMethodInts(ModuleDef module, MethodDef method)
        {
            EncodeMethodInts(module, method, false);
        }

        private void EncodeMethodInts(ModuleDef module, MethodDef method, bool aggressive)
        {
            var il = method.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {
                if (!engine.IsIntLoad(il[i])) continue;
                int val = engine.ExtractInt(il[i]);
                if (val == int.MinValue) continue;
                if (!aggressive && val >= -1 && val <= 8 && rng.Next(0, 3) != 0) continue;

                var replacement = BuildEncoding(val, aggressive);
                if (replacement == null || replacement.Count == 0) continue;

                il[i].OpCode = replacement[0].OpCode;
                il[i].Operand = replacement[0].Operand;
                for (int j = 1; j < replacement.Count; j++)
                    il.Insert(i + j, replacement[j]);
                i += replacement.Count - 1;
            }
        }

        private List<Instruction> BuildEncoding(int val)
        {
            return BuildEncoding(val, false);
        }

        private List<Instruction> BuildEncoding(int val, bool aggressive)
        {

            int depth;
            if (engine.cfg != null && engine.cfg.MaximumEncryption)
                depth = rng.Next(5, 9);
            else if (aggressive)
                depth = rng.Next(2, 4);
            else
                depth = rng.Next(0, 3);
            int currentTarget = val;
            var wraps = new List<Instruction>();
            for (int d = 0; d < depth; d++)
            {
                int wrapKey = rng.Next(int.MinValue, int.MaxValue);
                int wrapMode = rng.Next(0, 4);
                var newOps = new List<Instruction>();
                switch (wrapMode)
                {
                    case 0:
                        currentTarget = currentTarget ^ wrapKey;
                        newOps.Add(Instruction.Create(DnOpCodes.Ldc_I4, wrapKey));
                        newOps.Add(Instruction.Create(DnOpCodes.Xor));
                        break;
                    case 1:
                        currentTarget = unchecked(currentTarget - wrapKey);
                        newOps.Add(Instruction.Create(DnOpCodes.Ldc_I4, wrapKey));
                        newOps.Add(Instruction.Create(DnOpCodes.Add));
                        break;
                    case 2:
                        currentTarget = unchecked(currentTarget + wrapKey);
                        newOps.Add(Instruction.Create(DnOpCodes.Ldc_I4, wrapKey));
                        newOps.Add(Instruction.Create(DnOpCodes.Sub));
                        break;
                    default:
                        currentTarget = ~currentTarget;
                        newOps.Add(Instruction.Create(DnOpCodes.Not));
                        break;
                }
                newOps.AddRange(wraps);
                wraps = newOps;
            }
            var insts = BuildSingleLayer(currentTarget);
            insts.AddRange(wraps);
            return insts;
        }

        private List<Instruction> BuildSingleLayer(int val)
        {
            int variant = rng.Next(0, 18);
            var replacement = new List<Instruction>();
            switch (variant)
            {
                case 0:
                    int xk = rng.Next(int.MinValue, int.MaxValue);
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, xk));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, xk ^ val));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 1:
                    int a1 = rng.Next(100000, 9999999);
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, a1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, unchecked(a1 - val)));
                    replacement.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                case 2:
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~val));
                    replacement.Add(Instruction.Create(DnOpCodes.Not));
                    break;
                case 3:
                    int s = rng.Next(1, 8);
                    int shifted = val << s;
                    if ((shifted >> s) == val)
                    {
                        replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, shifted));
                        replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, s));
                        replacement.Add(Instruction.Create(DnOpCodes.Shr));
                    }
                    else
                    {
                        int sfk = rng.Next(int.MinValue, int.MaxValue);
                        replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, sfk));
                        replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, sfk ^ val));
                        replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    }
                    break;
                case 4:
                    int x1 = rng.Next(int.MinValue, int.MaxValue);
                    int x2 = rng.Next(int.MinValue, int.MaxValue);
                    int x3 = val ^ x1 ^ x2;
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, x1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, x2));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, x3));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                case 5:
                    int b1 = rng.Next(1000, 999999);
                    int b2 = rng.Next(1000, 999999);
                    int bres = unchecked(val - b1 + b2);
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, b1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, b2));
                    replacement.Add(Instruction.Create(DnOpCodes.Sub));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, bres));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 6:
                    int mk = rng.Next(int.MinValue, int.MaxValue);
                    int op1 = val & mk;
                    int op2 = val & ~mk;
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, op1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, op2));
                    replacement.Add(Instruction.Create(DnOpCodes.Or));
                    break;
                case 7:
                    int nk = rng.Next(int.MinValue, int.MaxValue);
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, nk));
                    replacement.Add(Instruction.Create(DnOpCodes.Not));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, unchecked(val - (~nk))));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                case 8:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int correction = unchecked(val - ((u1 ^ u2) + ((u1 & u2) << 1)));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.And));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    replacement.Add(Instruction.Create(DnOpCodes.Shl));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                }
                case 9:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int correction = unchecked(val ^ ((u1 | u2) - (u1 & u2)));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.Or));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.And));
                    replacement.Add(Instruction.Create(DnOpCodes.Sub));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                }
                case 10:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int extra = unchecked(val - ((u1 & u2) + (u1 | u2)));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.And));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.Or));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, extra));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                }
                case 11:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int correction = unchecked(val - (~(u1 & u2) + (u1 | u2)));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.And));
                    replacement.Add(Instruction.Create(DnOpCodes.Not));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.Or));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                }
                case 12:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int correction = unchecked(val ^ ((~u1 & u2) ^ (u1 & ~u2)));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Not));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.And));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.Not));
                    replacement.Add(Instruction.Create(DnOpCodes.And));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                }
                case 13:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int u3 = rng.Next(int.MinValue, int.MaxValue);
                    int correction = unchecked(val ^ u1 ^ u2 ^ u3);
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u3));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                }
                case 14:
                {
                    int e = rng.Next(2, 1000);
                    int f = rng.Next(2, 1000);
                    int corr = unchecked(val ^ (e * f));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, e));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, f));
                    replacement.Add(Instruction.Create(DnOpCodes.Mul));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, corr));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                }
                case 15:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int correction = unchecked((~u1) - val);
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Not));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                    replacement.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
                }
                case 16:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int avg2 = unchecked((u1 + u2));
                    int correction = unchecked(val - avg2);
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                    replacement.Add(Instruction.Create(DnOpCodes.Add));
                    break;
                }
                default:
                {
                    int u1 = rng.Next(int.MinValue, int.MaxValue);
                    int u2 = rng.Next(int.MinValue, int.MaxValue);
                    int correction = unchecked(val ^ u1 ^ ~u2);
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u1));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, u2));
                    replacement.Add(Instruction.Create(DnOpCodes.Not));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    replacement.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                    replacement.Add(Instruction.Create(DnOpCodes.Xor));
                    break;
                }
            }
            return replacement;
        }
    }
}

