using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class MutationEncodingProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal MutationEncodingProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyMutationEncoding(ModuleDef module)
        {
            for (int pass = 0; pass < 2; pass++)
            {
                foreach (TypeDef type in module.GetTypes())
                {
                    if (engine.IsCompilerGenerated(type)) continue;
                    foreach (MethodDef method in type.Methods)
                    {
                        if (!engine.CanProcessMethod(method)) continue;
                        if (!IsMethodSafeToMutate(method)) continue;
                        try
                        {
                            MutateMethod(module, method);
                            method.Body.SimplifyBranches();
                            method.Body.OptimizeBranches();
                        }
                        catch { }
                    }
                }
            }
        }

        private bool IsMethodSafeToMutate(MethodDef method)
        {
            if (method.MethodSig != null)
            {
                if (!IsIntSafeType(method.MethodSig.RetType)) return false;
                if (method.MethodSig.Params != null)
                {
                    foreach (var p in method.MethodSig.Params)
                        if (!IsIntSafeType(p)) return false;
                }
            }
            if (method.Body == null) return false;
            if (method.Body.Variables != null)
            {
                foreach (var lv in method.Body.Variables)
                    if (!IsIntSafeType(lv.Type)) return false;
            }
            foreach (var ins in method.Body.Instructions)
            {
                var c = ins.OpCode.Code;
                if (c == Code.Ldc_R4 || c == Code.Ldc_R8 || c == Code.Ldc_I8) return false;
                if (c == Code.Conv_R4 || c == Code.Conv_R8 || c == Code.Conv_I8 ||
                    c == Code.Conv_U8 ||
                    c == Code.Conv_Ovf_I8 || c == Code.Conv_Ovf_I8_Un ||
                    c == Code.Conv_Ovf_U8 || c == Code.Conv_Ovf_U8_Un ||
                    c == Code.Conv_R_Un) return false;
                if (c == Code.Ldind_R4 || c == Code.Ldind_R8 ||
                    c == Code.Ldind_I8) return false;
                if (c == Code.Stind_R4 || c == Code.Stind_R8 ||
                    c == Code.Stind_I8) return false;
                if (c == Code.Ldelem_R4 || c == Code.Ldelem_R8 ||
                    c == Code.Ldelem_I8) return false;
                if (c == Code.Stelem_R4 || c == Code.Stelem_R8 ||
                    c == Code.Stelem_I8) return false;
                var op = ins.Operand;
                if (op is IField)
                {
                    var fld = (IField)op;
                    if (fld.FieldSig != null && !IsIntSafeType(fld.FieldSig.Type)) return false;
                }
                else if (op is IMethod && !(op is MethodSpec))
                {
                    var meth = (IMethod)op;
                    if (meth.MethodSig != null)
                    {
                        if (!IsIntSafeType(meth.MethodSig.RetType)) return false;
                        if (meth.MethodSig.Params != null)
                        {
                            foreach (var p in meth.MethodSig.Params)
                                if (!IsIntSafeType(p)) return false;
                        }
                    }
                }
                else if (op is MethodSpec)
                {
                    return false;
                }
            }
            return true;
        }

        private bool IsIntSafeType(TypeSig sig)
        {
            if (sig == null) return true;
            var t = sig.RemovePinnedAndModifiers();
            if (t == null) return true;
            string fn = t.FullName;
            if (fn == "System.Int32" || fn == "System.UInt32" ||
                fn == "System.Boolean" || fn == "System.Char" ||
                fn == "System.Byte" || fn == "System.SByte" ||
                fn == "System.Int16" || fn == "System.UInt16" ||
                fn == "System.Void") return true;
            if (fn == "System.Single" || fn == "System.Double" ||
                fn == "System.Int64" || fn == "System.UInt64" ||
                fn == "System.IntPtr" || fn == "System.UIntPtr") return false;
            return true;
        }

        private void MutateMethod(ModuleDef module, MethodDef method)
        {
            var il = method.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode == DnOpCodes.Add && rng.Next(0, 2) == 0)
                {
                    int variant = rng.Next(0, 4);
                    switch (variant)
                    {
                        case 0:
                            il[i].OpCode = DnOpCodes.Sub;
                            il[i].Operand = null;
                            il.Insert(i, Instruction.Create(DnOpCodes.Neg));
                            i++;
                            break;
                        case 1:
                            il[i].OpCode = DnOpCodes.Sub;
                            il[i].Operand = null;
                            il.Insert(i, Instruction.Create(DnOpCodes.Neg));
                            int noise1 = rng.Next(int.MinValue, int.MaxValue);
                            il.Insert(i + 2, Instruction.Create(DnOpCodes.Ldc_I4, noise1));
                            il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, noise1));
                            il.Insert(i + 4, Instruction.Create(DnOpCodes.Xor));
                            il.Insert(i + 5, Instruction.Create(DnOpCodes.Add));
                            i += 5;
                            break;
                        case 2:
                            int junk = rng.Next(1000, 9999999);
                            il.Insert(i, Instruction.Create(DnOpCodes.Ldc_I4, junk));
                            il.Insert(i + 1, Instruction.Create(DnOpCodes.Add));
                            il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, junk));
                            il.Insert(i + 4, Instruction.Create(DnOpCodes.Sub));
                            i += 4;
                            break;
                        default:
                            il[i].OpCode = DnOpCodes.Sub;
                            il[i].Operand = null;
                            il.Insert(i, Instruction.Create(DnOpCodes.Neg));
                            int noise = rng.Next(int.MinValue, int.MaxValue);
                            il.Insert(i + 2, Instruction.Create(DnOpCodes.Ldc_I4, noise));
                            il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, noise));
                            il.Insert(i + 4, Instruction.Create(DnOpCodes.Xor));
                            il.Insert(i + 5, Instruction.Create(DnOpCodes.Add));
                            i += 5;
                            break;
                    }
                    continue;
                }

                if (il[i].OpCode == DnOpCodes.Sub && rng.Next(0, 2) == 0)
                {
                    int variant = rng.Next(0, 3);
                    switch (variant)
                    {
                        case 0:
                            il[i].OpCode = DnOpCodes.Add;
                            il[i].Operand = null;
                            il.Insert(i, Instruction.Create(DnOpCodes.Neg));
                            i++;
                            break;
                        case 1:
                            int junk = rng.Next(1000, 9999999);
                            il.Insert(i, Instruction.Create(DnOpCodes.Ldc_I4, junk));
                            il.Insert(i + 1, Instruction.Create(DnOpCodes.Add));
                            il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, junk));
                            il.Insert(i + 4, Instruction.Create(DnOpCodes.Add));
                            i += 4;
                            break;
                        default:
                            il[i].OpCode = DnOpCodes.Neg;
                            il[i].Operand = null;
                            il.Insert(i + 1, Instruction.Create(DnOpCodes.Add));
                            il.Insert(i + 2, Instruction.Create(DnOpCodes.Not));
                            il.Insert(i + 3, Instruction.Create(DnOpCodes.Not));
                            i += 3;
                            break;
                    }
                    continue;
                }

                if (il[i].OpCode == DnOpCodes.Xor && rng.Next(0, 2) == 0)
                {
                    int variant = rng.Next(0, 3);
                    switch (variant)
                    {
                        case 0:
                            int dummy = rng.Next(int.MinValue, int.MaxValue);
                            il.Insert(i, Instruction.Create(DnOpCodes.Ldc_I4, dummy));
                            il.Insert(i + 1, Instruction.Create(DnOpCodes.Xor));
                            il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, dummy));
                            il.Insert(i + 4, Instruction.Create(DnOpCodes.Xor));
                            i += 4;
                            break;
                        case 1:
                            int d2 = rng.Next(int.MinValue, int.MaxValue);
                            int d3 = rng.Next(int.MinValue, int.MaxValue);
                            il.Insert(i, Instruction.Create(DnOpCodes.Ldc_I4, d2));
                            il.Insert(i + 1, Instruction.Create(DnOpCodes.Xor));
                            il.Insert(i + 2, Instruction.Create(DnOpCodes.Ldc_I4, d3));
                            il.Insert(i + 3, Instruction.Create(DnOpCodes.Xor));
                            il.Insert(i + 5, Instruction.Create(DnOpCodes.Ldc_I4, d2 ^ d3));
                            il.Insert(i + 6, Instruction.Create(DnOpCodes.Xor));
                            i += 6;
                            break;
                        default:
                            int xn = rng.Next(int.MinValue, int.MaxValue);
                            il.Insert(i + 1, Instruction.Create(DnOpCodes.Not));
                            il.Insert(i + 2, Instruction.Create(DnOpCodes.Not));
                            il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, xn));
                            il.Insert(i + 4, Instruction.Create(DnOpCodes.Ldc_I4, xn));
                            il.Insert(i + 5, Instruction.Create(DnOpCodes.Xor));
                            il.Insert(i + 6, Instruction.Create(DnOpCodes.Add));
                            i += 6;
                            break;
                    }
                    continue;
                }

                if (il[i].OpCode == DnOpCodes.And && rng.Next(0, 3) == 0)
                {
                    int an = rng.Next(int.MinValue, int.MaxValue);
                    il.Insert(i + 1, Instruction.Create(DnOpCodes.Not));
                    il.Insert(i + 2, Instruction.Create(DnOpCodes.Not));
                    il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, an));
                    il.Insert(i + 4, Instruction.Create(DnOpCodes.Ldc_I4, an));
                    il.Insert(i + 5, Instruction.Create(DnOpCodes.Xor));
                    il.Insert(i + 6, Instruction.Create(DnOpCodes.Add));
                    i += 6;
                    continue;
                }

                if (il[i].OpCode == DnOpCodes.Or && rng.Next(0, 3) == 0)
                {
                    int on = rng.Next(int.MinValue, int.MaxValue);
                    il.Insert(i + 1, Instruction.Create(DnOpCodes.Not));
                    il.Insert(i + 2, Instruction.Create(DnOpCodes.Not));
                    il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, on));
                    il.Insert(i + 4, Instruction.Create(DnOpCodes.Ldc_I4, on));
                    il.Insert(i + 5, Instruction.Create(DnOpCodes.Xor));
                    il.Insert(i + 6, Instruction.Create(DnOpCodes.Add));
                    i += 6;
                    continue;
                }

                if (il[i].OpCode == DnOpCodes.Not && rng.Next(0, 3) == 0)
                {
                    il[i].OpCode = DnOpCodes.Ldc_I4;
                    il[i].Operand = -1;
                    il.Insert(i + 1, Instruction.Create(DnOpCodes.Xor));
                    i++;
                    continue;
                }

                if (il[i].OpCode == DnOpCodes.Neg && rng.Next(0, 3) == 0)
                {
                    il[i].OpCode = DnOpCodes.Not;
                    il[i].Operand = null;
                    il.Insert(i + 1, Instruction.Create(DnOpCodes.Ldc_I4_1));
                    il.Insert(i + 2, Instruction.Create(DnOpCodes.Add));
                    i += 2;
                    continue;
                }

                if (il[i].OpCode == DnOpCodes.Mul && rng.Next(0, 4) == 0)
                {
                    int identity = rng.Next(100000, 9999999);
                    il.Insert(i, Instruction.Create(DnOpCodes.Ldc_I4, identity));
                    il.Insert(i + 1, Instruction.Create(DnOpCodes.Ldc_I4, identity));
                    il.Insert(i + 2, Instruction.Create(DnOpCodes.Xor));
                    il.Insert(i + 3, Instruction.Create(DnOpCodes.Add));
                    i += 3;
                    continue;
                }

                if (engine.IsIntLoad(il[i]) && rng.Next(0, 5) == 0)
                {
                    int origVal = engine.ExtractInt(il[i]);
                    if (origVal != int.MinValue && Math.Abs(origVal) < 0x7FFFFF00)
                    {
                        int k1 = rng.Next(int.MinValue / 2, int.MaxValue / 2);
                        int k2 = rng.Next(int.MinValue / 2, int.MaxValue / 2);
                        int encoded = origVal ^ k1 ^ k2;
                        il[i].OpCode = DnOpCodes.Ldc_I4;
                        il[i].Operand = encoded;
                        il.Insert(i + 1, Instruction.Create(DnOpCodes.Ldc_I4, k1));
                        il.Insert(i + 2, Instruction.Create(DnOpCodes.Xor));
                        il.Insert(i + 3, Instruction.Create(DnOpCodes.Ldc_I4, k2));
                        il.Insert(i + 4, Instruction.Create(DnOpCodes.Xor));
                        i += 4;
                    }
                }
            }
        }

        private Local EnsureTempLocal(MethodDef method, ModuleDef module)
        {
            foreach (var loc in method.Body.Variables)
            {
                if (loc.Type.FullName == "System.Int32" && loc.Index >= method.Body.Variables.Count - 2)
                    return loc;
            }
            var newLocal = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(newLocal);
            return newLocal;
        }
    }
}

