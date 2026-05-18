using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System;
using dnlib.DotNet.Emit;
using dnlib.DotNet;
using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;

namespace MasonProtector.Core
{

    internal class VMObfuscationProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const byte VOP_NOP      = 0;
        private const byte VOP_PUSH_I4  = 1;
        private const byte VOP_ADD      = 2;
        private const byte VOP_SUB      = 3;
        private const byte VOP_MUL      = 4;
        private const byte VOP_XOR      = 5;
        private const byte VOP_AND      = 6;
        private const byte VOP_OR       = 7;
        private const byte VOP_NOT      = 8;
        private const byte VOP_NEG      = 9;
        private const byte VOP_POP      = 10;
        private const byte VOP_DUP      = 11;
        private const byte VOP_LDLOC    = 12;
        private const byte VOP_STLOC    = 13;
        private const byte VOP_LDARG    = 14;
        private const byte VOP_BR       = 15;
        private const byte VOP_BRFALSE  = 16;
        private const byte VOP_BRTRUE   = 17;
        private const byte VOP_CEQ      = 18;
        private const byte VOP_CGT      = 19;
        private const byte VOP_CGT_UN   = 20;
        private const byte VOP_CLT      = 21;
        private const byte VOP_CLT_UN   = 22;
        private const byte VOP_SHL      = 23;
        private const byte VOP_SHR      = 24;
        private const byte VOP_SHR_UN   = 25;
        private const byte VOP_DIV      = 26;
        private const byte VOP_DIV_UN   = 27;
        private const byte VOP_REM      = 28;
        private const byte VOP_REM_UN   = 29;
        private const byte VOP_RET      = 30;
        private const byte VOP_CONV_I1  = 31;
        private const byte VOP_CONV_U1  = 32;
        private const byte VOP_CONV_I2  = 33;
        private const byte VOP_CONV_U2  = 34;

        internal VMObfuscationProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyVMObfuscation(ModuleDef module)
        {
            var vmType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(vmType);
            engine.injectedTypes.Add(vmType);

            int[] opcodeMap = new int[256];
            for (int i = 0; i < 256; i++) opcodeMap[i] = i;
            for (int i = 255; i > 0; i--)
            {
                int j = rng.Next(0, i + 1);
                int t = opcodeMap[i]; opcodeMap[i] = opcodeMap[j]; opcodeMap[j] = t;
            }

            var bytecodeField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(new SZArraySig(module.CorLibTypes.Byte))),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmType.Fields.Add(bytecodeField);

            var dispatcher = BuildVMDispatcher(module, vmType, bytecodeField, opcodeMap);
            vmType.Methods.Add(dispatcher);
            engine.injectedMethods.Add(dispatcher);

            var collectedBytecodes = new List<KeyValuePair<int, byte[]>>();

            int virtualized = 0;
            foreach (TypeDef type in module.GetTypes().ToList())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods.ToList())
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (method.IsConstructor || method.IsStaticConstructor) continue;
                    if (!method.IsStatic) continue;
                    if (method.Body == null) continue;
                    if (method.Body.HasExceptionHandlers) continue;
                    if (method.HasGenericParameters) continue;
                    if (method.IsPinvokeImpl) continue;
                    if (method.Body.Instructions.Count < 4) continue;

                    int numLocals;
                    int numArgs;
                    bool returnsInt;
                    if (!IsVMCompatible(method, out numLocals, out numArgs, out returnsInt)) continue;

                    try
                    {
                        byte[] bc = EmitVMBytecode(method, opcodeMap);
                        if (bc == null || bc.Length == 0) continue;
                        byte xorKey = (byte)rng.Next(1, 255);
                        for (int b = 0; b < bc.Length; b++)
                        {
                            byte mask = (byte)(xorKey ^ (byte)b);
                            bc[b] ^= mask;
                        }

                        int slot = virtualized;
                        collectedBytecodes.Add(new KeyValuePair<int, byte[]>(slot, bc));

                        EmitVMStub(module, method, slot, xorKey, numLocals, numArgs, returnsInt, dispatcher);
                        engine.virtualizedMethods.Add(method);

                        virtualized++;
                    }
                    catch { }
                }
            }

            if (virtualized == 0) return;

            var initMethod = BuildVMInit(module, vmType, bytecodeField, collectedBytecodes, virtualized);
            vmType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);

            var modType = module.Types.FirstOrDefault(t => t.Name == "<Module>");
            if (modType != null)
                engine.InjectCallInCctor(module, modType, initMethod);
        }

        private bool IsIntType(TypeSig t)
        {
            if (t == null) return false;
            string fn = t.FullName;
            return fn == "System.Int32"  || fn == "System.UInt32"
                || fn == "System.Int16"  || fn == "System.UInt16"
                || fn == "System.SByte"  || fn == "System.Byte"
                || fn == "System.Boolean"|| fn == "System.Char";
        }

        private OpCode StubReturnConvOp(TypeSig t)
        {
            if (t == null) return null;
            string fn = t.FullName;
            if (fn == "System.SByte")   return DnOpCodes.Conv_I1;
            if (fn == "System.Byte"
             || fn == "System.Boolean") return DnOpCodes.Conv_U1;
            if (fn == "System.Int16")   return DnOpCodes.Conv_I2;
            if (fn == "System.UInt16"
             || fn == "System.Char")    return DnOpCodes.Conv_U2;
            return null;
        }

        private bool IsVoidType(TypeSig t)
        {
            return t != null && t.FullName == "System.Void";
        }

        private bool IsVMCompatible(MethodDef method, out int numLocals, out int numArgs, out bool returnsInt)
        {
            numLocals = 0;
            numArgs = 0;
            returnsInt = false;

            var ret = method.ReturnType;
            if (IsVoidType(ret)) returnsInt = false;
            else if (IsIntType(ret)) returnsInt = true;
            else return false;

            int argCount = 0;
            foreach (var p in method.Parameters)
            {
                if (p.IsHiddenThisParameter) return false;
                if (!IsIntType(p.Type)) return false;
                argCount++;
            }
            numArgs = argCount;

            if (method.Body.HasVariables)
            {
                foreach (var v in method.Body.Variables)
                {
                    if (!IsIntType(v.Type)) return false;
                }
                numLocals = method.Body.Variables.Count;
            }

            if (numArgs > 255 || numLocals > 255) return false;

            foreach (var inst in method.Body.Instructions)
            {
                if (!IsAllowedOpcode(inst.OpCode)) return false;
            }
            return true;
        }

        private bool IsAllowedOpcode(OpCode op)
        {
            if (op == DnOpCodes.Nop) return true;
            if (op == DnOpCodes.Ret) return true;
            if (op == DnOpCodes.Pop) return true;
            if (op == DnOpCodes.Dup) return true;
            if (IsLdcI4(op)) return true;
            if (IsLdarg(op)) return true;
            if (IsLdloc(op)) return true;
            if (IsStloc(op)) return true;
            if (op == DnOpCodes.Add || op == DnOpCodes.Sub || op == DnOpCodes.Mul) return true;
            if (op == DnOpCodes.Div || op == DnOpCodes.Div_Un) return true;
            if (op == DnOpCodes.Rem || op == DnOpCodes.Rem_Un) return true;
            if (op == DnOpCodes.Xor || op == DnOpCodes.And || op == DnOpCodes.Or) return true;
            if (op == DnOpCodes.Not || op == DnOpCodes.Neg) return true;
            if (op == DnOpCodes.Shl || op == DnOpCodes.Shr || op == DnOpCodes.Shr_Un) return true;
            if (op == DnOpCodes.Ceq || op == DnOpCodes.Cgt || op == DnOpCodes.Cgt_Un
                || op == DnOpCodes.Clt || op == DnOpCodes.Clt_Un) return true;
            if (op == DnOpCodes.Conv_I4 || op == DnOpCodes.Conv_U4) return true;
            if (op == DnOpCodes.Conv_I1 || op == DnOpCodes.Conv_U1) return true;
            if (op == DnOpCodes.Conv_I2 || op == DnOpCodes.Conv_U2) return true;
            if (op == DnOpCodes.Conv_I  || op == DnOpCodes.Conv_U)  return true;
            if (op == DnOpCodes.Br || op == DnOpCodes.Br_S) return true;
            if (op == DnOpCodes.Brfalse || op == DnOpCodes.Brfalse_S) return true;
            if (op == DnOpCodes.Brtrue || op == DnOpCodes.Brtrue_S) return true;
            if (op == DnOpCodes.Beq || op == DnOpCodes.Beq_S) return true;
            if (op == DnOpCodes.Bne_Un || op == DnOpCodes.Bne_Un_S) return true;
            if (op == DnOpCodes.Bgt || op == DnOpCodes.Bgt_S) return true;
            if (op == DnOpCodes.Bgt_Un || op == DnOpCodes.Bgt_Un_S) return true;
            if (op == DnOpCodes.Blt || op == DnOpCodes.Blt_S) return true;
            if (op == DnOpCodes.Blt_Un || op == DnOpCodes.Blt_Un_S) return true;
            if (op == DnOpCodes.Bge || op == DnOpCodes.Bge_S) return true;
            if (op == DnOpCodes.Bge_Un || op == DnOpCodes.Bge_Un_S) return true;
            if (op == DnOpCodes.Ble || op == DnOpCodes.Ble_S) return true;
            if (op == DnOpCodes.Ble_Un || op == DnOpCodes.Ble_Un_S) return true;
            return false;
        }

        private bool IsLdcI4(OpCode op)
        {
            return op == DnOpCodes.Ldc_I4 || op == DnOpCodes.Ldc_I4_S
                || op == DnOpCodes.Ldc_I4_0 || op == DnOpCodes.Ldc_I4_1
                || op == DnOpCodes.Ldc_I4_2 || op == DnOpCodes.Ldc_I4_3
                || op == DnOpCodes.Ldc_I4_4 || op == DnOpCodes.Ldc_I4_5
                || op == DnOpCodes.Ldc_I4_6 || op == DnOpCodes.Ldc_I4_7
                || op == DnOpCodes.Ldc_I4_8 || op == DnOpCodes.Ldc_I4_M1;
        }

        private bool IsLdarg(OpCode op)
        {
            return op == DnOpCodes.Ldarg || op == DnOpCodes.Ldarg_S
                || op == DnOpCodes.Ldarg_0 || op == DnOpCodes.Ldarg_1
                || op == DnOpCodes.Ldarg_2 || op == DnOpCodes.Ldarg_3;
        }

        private bool IsLdloc(OpCode op)
        {
            return op == DnOpCodes.Ldloc || op == DnOpCodes.Ldloc_S
                || op == DnOpCodes.Ldloc_0 || op == DnOpCodes.Ldloc_1
                || op == DnOpCodes.Ldloc_2 || op == DnOpCodes.Ldloc_3;
        }

        private bool IsStloc(OpCode op)
        {
            return op == DnOpCodes.Stloc || op == DnOpCodes.Stloc_S
                || op == DnOpCodes.Stloc_0 || op == DnOpCodes.Stloc_1
                || op == DnOpCodes.Stloc_2 || op == DnOpCodes.Stloc_3;
        }

        private int GetArgIndex(Instruction inst)
        {
            var op = inst.OpCode;
            if (op == DnOpCodes.Ldarg_0) return 0;
            if (op == DnOpCodes.Ldarg_1) return 1;
            if (op == DnOpCodes.Ldarg_2) return 2;
            if (op == DnOpCodes.Ldarg_3) return 3;
            var p = inst.Operand as Parameter;
            if (p != null) return p.Index;
            return Convert.ToInt32(inst.Operand);
        }

        private int GetLocalIndex(Instruction inst)
        {
            var op = inst.OpCode;
            if (op == DnOpCodes.Ldloc_0 || op == DnOpCodes.Stloc_0) return 0;
            if (op == DnOpCodes.Ldloc_1 || op == DnOpCodes.Stloc_1) return 1;
            if (op == DnOpCodes.Ldloc_2 || op == DnOpCodes.Stloc_2) return 2;
            if (op == DnOpCodes.Ldloc_3 || op == DnOpCodes.Stloc_3) return 3;
            var l = inst.Operand as Local;
            if (l != null) return l.Index;
            return Convert.ToInt32(inst.Operand);
        }

        private void EmitInt32LE(List<byte> bc, int v)
        {
            bc.Add((byte)(v & 0xFF));
            bc.Add((byte)((v >> 8) & 0xFF));
            bc.Add((byte)((v >> 16) & 0xFF));
            bc.Add((byte)((v >> 24) & 0xFF));
        }

        private byte[] EmitVMBytecode(MethodDef method, int[] opcodeMap)
        {
            var bc = new List<byte>();
            var ipOfIl = new Dictionary<Instruction, int>();
            var pendingBranches = new List<KeyValuePair<int, Instruction>>();

            foreach (var inst in method.Body.Instructions)
            {
                ipOfIl[inst] = bc.Count;
                var op = inst.OpCode;

                if (op == DnOpCodes.Nop || op == DnOpCodes.Conv_I4 || op == DnOpCodes.Conv_U4
                    || op == DnOpCodes.Conv_I || op == DnOpCodes.Conv_U)
                {
                    bc.Add((byte)opcodeMap[VOP_NOP]);
                }
                else if (op == DnOpCodes.Conv_I1) bc.Add((byte)opcodeMap[VOP_CONV_I1]);
                else if (op == DnOpCodes.Conv_U1) bc.Add((byte)opcodeMap[VOP_CONV_U1]);
                else if (op == DnOpCodes.Conv_I2) bc.Add((byte)opcodeMap[VOP_CONV_I2]);
                else if (op == DnOpCodes.Conv_U2) bc.Add((byte)opcodeMap[VOP_CONV_U2]);
                else if (op == DnOpCodes.Ret)
                {
                    bc.Add((byte)opcodeMap[VOP_RET]);
                }
                else if (IsLdcI4(op))
                {
                    int val = inst.GetLdcI4Value();
                    bc.Add((byte)opcodeMap[VOP_PUSH_I4]);
                    EmitInt32LE(bc, val);
                }
                else if (op == DnOpCodes.Add) bc.Add((byte)opcodeMap[VOP_ADD]);
                else if (op == DnOpCodes.Sub) bc.Add((byte)opcodeMap[VOP_SUB]);
                else if (op == DnOpCodes.Mul) bc.Add((byte)opcodeMap[VOP_MUL]);
                else if (op == DnOpCodes.Div) bc.Add((byte)opcodeMap[VOP_DIV]);
                else if (op == DnOpCodes.Div_Un) bc.Add((byte)opcodeMap[VOP_DIV_UN]);
                else if (op == DnOpCodes.Rem) bc.Add((byte)opcodeMap[VOP_REM]);
                else if (op == DnOpCodes.Rem_Un) bc.Add((byte)opcodeMap[VOP_REM_UN]);
                else if (op == DnOpCodes.Xor) bc.Add((byte)opcodeMap[VOP_XOR]);
                else if (op == DnOpCodes.And) bc.Add((byte)opcodeMap[VOP_AND]);
                else if (op == DnOpCodes.Or)  bc.Add((byte)opcodeMap[VOP_OR]);
                else if (op == DnOpCodes.Not) bc.Add((byte)opcodeMap[VOP_NOT]);
                else if (op == DnOpCodes.Neg) bc.Add((byte)opcodeMap[VOP_NEG]);
                else if (op == DnOpCodes.Shl) bc.Add((byte)opcodeMap[VOP_SHL]);
                else if (op == DnOpCodes.Shr) bc.Add((byte)opcodeMap[VOP_SHR]);
                else if (op == DnOpCodes.Shr_Un) bc.Add((byte)opcodeMap[VOP_SHR_UN]);
                else if (op == DnOpCodes.Pop) bc.Add((byte)opcodeMap[VOP_POP]);
                else if (op == DnOpCodes.Dup) bc.Add((byte)opcodeMap[VOP_DUP]);
                else if (op == DnOpCodes.Ceq) bc.Add((byte)opcodeMap[VOP_CEQ]);
                else if (op == DnOpCodes.Cgt) bc.Add((byte)opcodeMap[VOP_CGT]);
                else if (op == DnOpCodes.Cgt_Un) bc.Add((byte)opcodeMap[VOP_CGT_UN]);
                else if (op == DnOpCodes.Clt) bc.Add((byte)opcodeMap[VOP_CLT]);
                else if (op == DnOpCodes.Clt_Un) bc.Add((byte)opcodeMap[VOP_CLT_UN]);
                else if (IsLdarg(op))
                {
                    int idx = GetArgIndex(inst);
                    if (idx < 0 || idx > 255) return null;
                    bc.Add((byte)opcodeMap[VOP_LDARG]);
                    bc.Add((byte)idx);
                }
                else if (IsLdloc(op))
                {
                    int idx = GetLocalIndex(inst);
                    if (idx < 0 || idx > 255) return null;
                    bc.Add((byte)opcodeMap[VOP_LDLOC]);
                    bc.Add((byte)idx);
                }
                else if (IsStloc(op))
                {
                    int idx = GetLocalIndex(inst);
                    if (idx < 0 || idx > 255) return null;
                    if (idx < method.Body.Variables.Count)
                    {
                        var lty = method.Body.Variables[idx].Type;
                        if (lty != null)
                        {
                            string lfn = lty.FullName;
                            if (lfn == "System.SByte")    bc.Add((byte)opcodeMap[VOP_CONV_I1]);
                            else if (lfn == "System.Byte"
                                  || lfn == "System.Boolean") bc.Add((byte)opcodeMap[VOP_CONV_U1]);
                            else if (lfn == "System.Int16") bc.Add((byte)opcodeMap[VOP_CONV_I2]);
                            else if (lfn == "System.UInt16"
                                  || lfn == "System.Char")   bc.Add((byte)opcodeMap[VOP_CONV_U2]);
                        }
                    }
                    bc.Add((byte)opcodeMap[VOP_STLOC]);
                    bc.Add((byte)idx);
                }
                else if (op == DnOpCodes.Br || op == DnOpCodes.Br_S)
                {
                    bc.Add((byte)opcodeMap[VOP_BR]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Brfalse || op == DnOpCodes.Brfalse_S)
                {
                    bc.Add((byte)opcodeMap[VOP_BRFALSE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Brtrue || op == DnOpCodes.Brtrue_S)
                {
                    bc.Add((byte)opcodeMap[VOP_BRTRUE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Beq || op == DnOpCodes.Beq_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CEQ]);
                    bc.Add((byte)opcodeMap[VOP_BRTRUE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Bne_Un || op == DnOpCodes.Bne_Un_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CEQ]);
                    bc.Add((byte)opcodeMap[VOP_BRFALSE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Bgt || op == DnOpCodes.Bgt_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CGT]);
                    bc.Add((byte)opcodeMap[VOP_BRTRUE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Bgt_Un || op == DnOpCodes.Bgt_Un_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CGT_UN]);
                    bc.Add((byte)opcodeMap[VOP_BRTRUE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Blt || op == DnOpCodes.Blt_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CLT]);
                    bc.Add((byte)opcodeMap[VOP_BRTRUE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Blt_Un || op == DnOpCodes.Blt_Un_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CLT_UN]);
                    bc.Add((byte)opcodeMap[VOP_BRTRUE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Bge || op == DnOpCodes.Bge_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CLT]);
                    bc.Add((byte)opcodeMap[VOP_BRFALSE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Bge_Un || op == DnOpCodes.Bge_Un_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CLT_UN]);
                    bc.Add((byte)opcodeMap[VOP_BRFALSE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Ble || op == DnOpCodes.Ble_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CGT]);
                    bc.Add((byte)opcodeMap[VOP_BRFALSE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Ble_Un || op == DnOpCodes.Ble_Un_S)
                {
                    bc.Add((byte)opcodeMap[VOP_CGT_UN]);
                    bc.Add((byte)opcodeMap[VOP_BRFALSE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else
                {
                    return null;
                }
            }

            foreach (var pb in pendingBranches)
            {
                var target = pb.Value;
                if (target == null || !ipOfIl.ContainsKey(target)) return null;
                int targetIp = ipOfIl[target];
                bc[pb.Key]     = (byte)(targetIp & 0xFF);
                bc[pb.Key + 1] = (byte)((targetIp >> 8) & 0xFF);
                bc[pb.Key + 2] = (byte)((targetIp >> 16) & 0xFF);
                bc[pb.Key + 3] = (byte)((targetIp >> 24) & 0xFF);
            }

            return bc.ToArray();
        }

        private void EmitVMStub(ModuleDef module, MethodDef method, int slot, byte xorKey,
            int numLocals, int numArgs, bool returnsInt, MethodDef dispatcher)
        {
            method.Body.Instructions.Clear();
            method.Body.Variables.Clear();
            method.Body.ExceptionHandlers.Clear();
            method.Body.InitLocals = true;

            var il = method.Body.Instructions;
            var int32Type = module.CorLibTypes.Int32.TypeDefOrRef;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, slot));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)xorKey));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, numLocals));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, numArgs));
            il.Add(Instruction.Create(DnOpCodes.Newarr, int32Type));
            for (int i = 0; i < numArgs; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[i]));
                il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
            }

            il.Add(Instruction.Create(DnOpCodes.Call, dispatcher));

            if (returnsInt)
            {
                var retConv = StubReturnConvOp(method.ReturnType);
                if (retConv != null)
                    il.Add(Instruction.Create(retConv));
                il.Add(Instruction.Create(DnOpCodes.Ret));
            }
            else
            {
                il.Add(Instruction.Create(DnOpCodes.Pop));
                il.Add(Instruction.Create(DnOpCodes.Ret));
            }
        }

        private MethodDef BuildVMDispatcher(ModuleDef module, TypeDef vmType,
            FieldDef bytecodeField, int[] opcodeMap)
        {
            var int32 = module.CorLibTypes.Int32;
            var int32Arr = new SZArraySig(int32);
            var byteArr = new SZArraySig(module.CorLibTypes.Byte);

            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(int32, int32, int32, int32, int32Arr),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(byteArr));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(int32Arr));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(int32Arr));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(int32));

            const int LOC_CODE   = 0;
            const int LOC_IP     = 1;
            const int LOC_OP     = 2;
            const int LOC_STACK  = 3;
            const int LOC_SP     = 4;
            const int LOC_LOCALS = 5;
            const int LOC_T1     = 6;
            const int LOC_T2     = 7;

            const int ARG_SLOT      = 0;
            const int ARG_KEY       = 1;
            const int ARG_NUMLOCALS = 2;
            const int ARG_ARGS      = 3;

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, bytecodeField));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_SLOT]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_CODE]));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 1024));
            il.Add(Instruction.Create(DnOpCodes.Newarr, int32.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_STACK]));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));

            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_NUMLOCALS]));
            il.Add(Instruction.Create(DnOpCodes.Newarr, int32.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_LOCALS]));

            var loopStart = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]);
            var loopEndRet = Instruction.Create(DnOpCodes.Nop);
            var advanceIp1 = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]);

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Bge, loopEndRet));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_KEY]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_OP]));

            var blkPush     = Instruction.Create(DnOpCodes.Nop);
            var blkAdd      = Instruction.Create(DnOpCodes.Nop);
            var blkSub      = Instruction.Create(DnOpCodes.Nop);
            var blkMul      = Instruction.Create(DnOpCodes.Nop);
            var blkDiv      = Instruction.Create(DnOpCodes.Nop);
            var blkDivUn    = Instruction.Create(DnOpCodes.Nop);
            var blkRem      = Instruction.Create(DnOpCodes.Nop);
            var blkRemUn    = Instruction.Create(DnOpCodes.Nop);
            var blkXor      = Instruction.Create(DnOpCodes.Nop);
            var blkAnd      = Instruction.Create(DnOpCodes.Nop);
            var blkOr       = Instruction.Create(DnOpCodes.Nop);
            var blkNot      = Instruction.Create(DnOpCodes.Nop);
            var blkNeg      = Instruction.Create(DnOpCodes.Nop);
            var blkPop      = Instruction.Create(DnOpCodes.Nop);
            var blkDup      = Instruction.Create(DnOpCodes.Nop);
            var blkLdloc    = Instruction.Create(DnOpCodes.Nop);
            var blkStloc    = Instruction.Create(DnOpCodes.Nop);
            var blkLdarg    = Instruction.Create(DnOpCodes.Nop);
            var blkBr       = Instruction.Create(DnOpCodes.Nop);
            var blkBrFalse  = Instruction.Create(DnOpCodes.Nop);
            var blkBrTrue   = Instruction.Create(DnOpCodes.Nop);
            var blkCeq      = Instruction.Create(DnOpCodes.Nop);
            var blkCgt      = Instruction.Create(DnOpCodes.Nop);
            var blkCgtUn    = Instruction.Create(DnOpCodes.Nop);
            var blkClt      = Instruction.Create(DnOpCodes.Nop);
            var blkCltUn    = Instruction.Create(DnOpCodes.Nop);
            var blkShl      = Instruction.Create(DnOpCodes.Nop);
            var blkShr      = Instruction.Create(DnOpCodes.Nop);
            var blkShrUn    = Instruction.Create(DnOpCodes.Nop);
            var blkConvI1   = Instruction.Create(DnOpCodes.Nop);
            var blkConvU1   = Instruction.Create(DnOpCodes.Nop);
            var blkConvI2   = Instruction.Create(DnOpCodes.Nop);
            var blkConvU2   = Instruction.Create(DnOpCodes.Nop);

            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_RET],     loopEndRet);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_PUSH_I4], blkPush);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_ADD],     blkAdd);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_SUB],     blkSub);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_MUL],     blkMul);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_DIV],     blkDiv);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_DIV_UN],  blkDivUn);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_REM],     blkRem);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_REM_UN],  blkRemUn);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_XOR],     blkXor);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_AND],     blkAnd);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_OR],      blkOr);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_NOT],     blkNot);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_NEG],     blkNeg);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_POP],     blkPop);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_DUP],     blkDup);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_LDLOC],   blkLdloc);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_STLOC],   blkStloc);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_LDARG],   blkLdarg);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_BR],      blkBr);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_BRFALSE], blkBrFalse);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_BRTRUE],  blkBrTrue);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CEQ],     blkCeq);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CGT],     blkCgt);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CGT_UN],  blkCgtUn);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CLT],     blkClt);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CLT_UN],  blkCltUn);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_SHL],     blkShl);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_SHR],     blkShr);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_SHR_UN],  blkShrUn);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CONV_I1], blkConvI1);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CONV_U1], blkConvU1);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CONV_I2], blkConvI2);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CONV_U2], blkConvU2);

            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkPush);
            EmitReadInt32(il, method, LOC_CODE, LOC_IP, ARG_KEY, 1, LOC_T1);
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 5));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            EmitBinaryOp(il, method, blkAdd,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Add, advanceIp1);
            EmitBinaryOp(il, method, blkSub,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Sub, advanceIp1);
            EmitBinaryOp(il, method, blkMul,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Mul, advanceIp1);
            EmitBinaryOp(il, method, blkDiv,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Div, advanceIp1);
            EmitBinaryOp(il, method, blkDivUn,  LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Div_Un, advanceIp1);
            EmitBinaryOp(il, method, blkRem,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Rem, advanceIp1);
            EmitBinaryOp(il, method, blkRemUn,  LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Rem_Un, advanceIp1);
            EmitBinaryOp(il, method, blkXor,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Xor, advanceIp1);
            EmitBinaryOp(il, method, blkAnd,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.And, advanceIp1);
            EmitBinaryOp(il, method, blkOr,     LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Or,  advanceIp1);
            EmitBinaryOp(il, method, blkShl,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Shl, advanceIp1);
            EmitBinaryOp(il, method, blkShr,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Shr, advanceIp1);
            EmitBinaryOp(il, method, blkShrUn,  LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Shr_Un, advanceIp1);

            EmitCmpOp(il, method, blkCeq,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Ceq,    advanceIp1);
            EmitCmpOp(il, method, blkCgt,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Cgt,    advanceIp1);
            EmitCmpOp(il, method, blkCgtUn,  LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Cgt_Un, advanceIp1);
            EmitCmpOp(il, method, blkClt,    LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Clt,    advanceIp1);
            EmitCmpOp(il, method, blkCltUn,  LOC_STACK, LOC_SP, LOC_T1, LOC_T2, DnOpCodes.Clt_Un, advanceIp1);

            il.Add(blkNot);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkNeg);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Neg));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkConvI1);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Conv_I1));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkConvU1);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkConvI2);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Conv_I2));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkConvU2);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFFFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkPop);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkDup);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, advanceIp1));

            il.Add(blkLdloc);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_KEY]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T2]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_LOCALS]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T2]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(blkStloc);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_KEY]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T2]));
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_LOCALS]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T2]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(blkLdarg);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_KEY]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T2]));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_ARGS]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T2]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(blkBr);
            EmitReadInt32(il, method, LOC_CODE, LOC_IP, ARG_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(blkBrFalse);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T2);
            EmitReadInt32(il, method, LOC_CODE, LOC_IP, ARG_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T2]));
            var brfNotTaken = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]);
            il.Add(Instruction.Create(DnOpCodes.Brtrue, brfNotTaken));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));
            il.Add(brfNotTaken);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 5));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(blkBrTrue);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T2);
            EmitReadInt32(il, method, LOC_CODE, LOC_IP, ARG_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T2]));
            var brtNotTaken = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]);
            il.Add(Instruction.Create(DnOpCodes.Brfalse, brtNotTaken));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));
            il.Add(brtNotTaken);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 5));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(advanceIp1);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(loopEndRet);
            var afterRet = Instruction.Create(DnOpCodes.Ret);
            var emptyStack = Instruction.Create(DnOpCodes.Ldc_I4_0);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ble, emptyStack));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Br, afterRet));
            il.Add(emptyStack);
            il.Add(afterRet);

            return method;
        }

        private void EmitDispatchEntry(IList<Instruction> il, Local opLocal, int opcodeValue, Instruction target)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldloc, opLocal));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, opcodeValue));
            il.Add(Instruction.Create(DnOpCodes.Beq, target));
        }

        private void EmitStackPush(IList<Instruction> il, MethodDef method, int LOC_STACK, int LOC_SP, int LOC_VAL)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_VAL]));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
        }

        private void EmitStackPop(IList<Instruction> il, MethodDef method, int LOC_STACK, int LOC_SP, int LOC_DEST)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST]));
        }

        private void EmitReadInt32(IList<Instruction> il, MethodDef method, int LOC_CODE, int LOC_IP, int ARG_KEY, int offset, int LOC_DEST)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST]));
            for (int i = 0; i < 4; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_DEST]));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, offset + i));
                il.Add(Instruction.Create(DnOpCodes.Add));
                il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
                il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_KEY]));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, offset + i));
                il.Add(Instruction.Create(DnOpCodes.Add));
                il.Add(Instruction.Create(DnOpCodes.Xor));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
                il.Add(Instruction.Create(DnOpCodes.And));
                il.Add(Instruction.Create(DnOpCodes.Xor));
                if (i > 0)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i * 8));
                    il.Add(Instruction.Create(DnOpCodes.Shl));
                }
                il.Add(Instruction.Create(DnOpCodes.Or));
                il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST]));
            }
        }

        private void EmitBinaryOp(IList<Instruction> il, MethodDef method, Instruction blockStart,
            int LOC_STACK, int LOC_SP, int LOC_T1, int LOC_T2, OpCode binOp, Instruction afterTarget)
        {
            il.Add(blockStart);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T2);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T2]));
            il.Add(Instruction.Create(binOp));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, afterTarget));
        }

        private void EmitCmpOp(IList<Instruction> il, MethodDef method, Instruction blockStart,
            int LOC_STACK, int LOC_SP, int LOC_T1, int LOC_T2, OpCode cmpOp, Instruction afterTarget)
        {
            il.Add(blockStart);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T2);
            EmitStackPop(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T2]));
            il.Add(Instruction.Create(cmpOp));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));
            EmitStackPush(il, method, LOC_STACK, LOC_SP, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Br, afterTarget));
        }

        private MethodDef BuildVMInit(ModuleDef module, TypeDef vmType,
            FieldDef bytecodeField, List<KeyValuePair<int, byte[]>> bytecodes, int totalSlots)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, totalSlots));
            il.Add(Instruction.Create(DnOpCodes.Newarr, new TypeSpecUser(new SZArraySig(module.CorLibTypes.Byte))));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, bytecodeField));

            foreach (var pair in bytecodes)
            {
                int slotIdx = pair.Key;
                byte[] bc = pair.Value;

                il.Add(Instruction.Create(DnOpCodes.Ldsfld, bytecodeField));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, slotIdx));

                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, bc.Length));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));

                for (int b = 0; b < bc.Length; b++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)bc[b]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
                }

                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }

    internal class VMObfuscationV2Protection
    {

        private const byte VOP_NOP        = 0;
        private const byte VOP_RET        = 1;
        private const byte VOP_LDARG      = 2;
        private const byte VOP_STARG      = 3;
        private const byte VOP_LDLOC      = 4;
        private const byte VOP_STLOC      = 5;
        private const byte VOP_POP        = 6;
        private const byte VOP_DUP        = 7;
        private const byte VOP_LDNULL     = 8;
        private const byte VOP_LDC_I4     = 9;
        private const byte VOP_LDSTR      = 10;
        private const byte VOP_LDSFLD     = 11;
        private const byte VOP_STSFLD     = 12;
        private const byte VOP_LDFLD      = 13;
        private const byte VOP_STFLD      = 14;
        private const byte VOP_CALL       = 15;
        private const byte VOP_CALLVIRT   = 16;
        private const byte VOP_NEWOBJ     = 17;
        private const byte VOP_NEWARR     = 18;
        private const byte VOP_LDLEN      = 19;
        private const byte VOP_LDELEM_REF = 20;
        private const byte VOP_STELEM_REF = 21;
        private const byte VOP_BR         = 22;
        private const byte VOP_BRTRUE     = 23;
        private const byte VOP_BRFALSE    = 24;
        private const byte VOP_THROW      = 25;
        private const byte VOP_BOX        = 26;
        private const byte VOP_UNBOX_ANY  = 27;
        private const byte VOP_CASTCLASS  = 28;
        private const byte VOP_ISINST     = 29;
        private const byte VOP_ADD        = 30;
        private const byte VOP_SUB        = 31;
        private const byte VOP_MUL        = 32;
        private const byte VOP_DIV        = 33;
        private const byte VOP_REM        = 34;
        private const byte VOP_AND        = 35;
        private const byte VOP_OR         = 36;
        private const byte VOP_XOR        = 37;
        private const byte VOP_NEG        = 38;
        private const byte VOP_NOT        = 39;
        private const byte VOP_SHL        = 40;
        private const byte VOP_SHR        = 41;
        private const byte VOP_CEQ        = 42;
        private const byte VOP_CGT        = 43;
        private const byte VOP_CLT        = 44;

        private const int OP_COUNT = 45;

        private Obfuscation engine;
        private Random rng;

        internal VMObfuscationV2Protection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyVMObfuscationV2(ModuleDef module)
        {

            var candidates = new List<MethodDef>();
            foreach (TypeDef type in module.GetTypes().ToList())
            {
                if (engine.IsCompilerGenerated(type)) continue;

                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef m in type.Methods.ToList())
                {
                    if (engine.IsMethodUserExcluded(m)) continue;
                    if (IsCandidate(m)) candidates.Add(m);
                }
            }
            if (candidates.Count == 0) return;

            var vmType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(vmType);
            engine.injectedTypes.Add(vmType);

            int[] opcodeMap = new int[256];
            for (int i = 0; i < 256; i++) opcodeMap[i] = i;
            for (int i = 255; i > 0; i--)
            {
                int j = rng.Next(0, i + 1);
                int t = opcodeMap[i]; opcodeMap[i] = opcodeMap[j]; opcodeMap[j] = t;
            }

            var byteArrArrSig = new SZArraySig(new SZArraySig(module.CorLibTypes.Byte));
            var byteArrSig    = new SZArraySig(module.CorLibTypes.Byte);
            var stringArrSig  = new SZArraySig(module.CorLibTypes.String);

            var methodBaseTypeRef = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase");
            var typeTypeRef       = module.CorLibTypes.GetTypeRef("System", "Type");
            var methodBaseArrSig  = new SZArraySig(new ClassSig(methodBaseTypeRef));
            var typeArrSig        = new SZArraySig(new ClassSig(typeTypeRef));

            var fldCode = new FieldDefUser(engine.MakeName(),
                new FieldSig(byteArrArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmType.Fields.Add(fldCode);

            var fldKeys = new FieldDefUser(engine.MakeName(),
                new FieldSig(byteArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmType.Fields.Add(fldKeys);

            var fldNumLocals = new FieldDefUser(engine.MakeName(),
                new FieldSig(byteArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmType.Fields.Add(fldNumLocals);

            var fldStrings = new FieldDefUser(engine.MakeName(),
                new FieldSig(stringArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmType.Fields.Add(fldStrings);

            var fldMethods = new FieldDefUser(engine.MakeName(),
                new FieldSig(methodBaseArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmType.Fields.Add(fldMethods);

            var fldTypes = new FieldDefUser(engine.MakeName(),
                new FieldSig(typeArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmType.Fields.Add(fldTypes);

            var stringPool = new List<string>();
            var stringIndex = new Dictionary<string, int>(StringComparer.Ordinal);
            var methodPool = new List<IMethod>();
            var methodIndex = new Dictionary<uint, int>();
            var typePool = new List<ITypeDefOrRef>();
            var typeIndex = new Dictionary<uint, int>();

            var collectedCodes = new List<byte[]>();
            var collectedKeys = new List<byte>();
            var collectedNumLocals = new List<byte>();
            var actuallyVirtualized = new List<MethodDef>();
            var slotForMethod = new Dictionary<MethodDef, int>();

            foreach (var m in candidates)
            {
                int numLocals = m.Body.HasVariables ? m.Body.Variables.Count : 0;
                if (numLocals > 255) continue;

                byte[] bc;
                try
                {
                    bc = EmitBytecode(m, opcodeMap, stringPool, stringIndex,
                        methodPool, methodIndex, typePool, typeIndex);
                }
                catch { continue; }
                if (bc == null || bc.Length == 0) continue;

                byte xorKey = (byte)rng.Next(1, 255);
                for (int b = 0; b < bc.Length; b++)
                {
                    byte mask = (byte)(xorKey ^ (byte)b);
                    bc[b] ^= mask;
                }

                int slot = actuallyVirtualized.Count;
                slotForMethod[m] = slot;
                collectedCodes.Add(bc);
                collectedKeys.Add(xorKey);
                collectedNumLocals.Add((byte)numLocals);
                actuallyVirtualized.Add(m);
                engine.virtualizedMethods.Add(m);
            }

            if (actuallyVirtualized.Count == 0)
            {

                module.Types.Remove(vmType);
                engine.injectedTypes.Remove(vmType);
                return;
            }

            var dispatcher = BuildDispatcher(module, vmType, fldCode, fldKeys, fldNumLocals,
                fldStrings, fldMethods, fldTypes, opcodeMap);
            vmType.Methods.Add(dispatcher);
            engine.injectedMethods.Add(dispatcher);

            var initMethod = BuildInit(module, vmType, fldCode, fldKeys, fldNumLocals,
                fldStrings, fldMethods, fldTypes, collectedCodes, collectedKeys, collectedNumLocals,
                stringPool, methodPool, typePool);
            vmType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);

            var modType = module.Types.FirstOrDefault(t => t.Name == "<Module>");
            if (modType != null)
                engine.InjectCallInCctor(module, modType, initMethod);

            foreach (var m in actuallyVirtualized)
            {
                int slot = slotForMethod[m];
                EmitStub(module, m, slot, dispatcher);
            }
        }

        private bool IsCandidate(MethodDef m)
        {
            if (!engine.CanProcessMethod(m)) return false;
            if (engine.virtualizedMethods.Contains(m)) return false;
            if (m.IsConstructor || m.IsStaticConstructor) return false;
            if (!m.IsStatic) return false;
            if (m.HasGenericParameters) return false;
            if (m.IsPinvokeImpl) return false;
            if (m.Body == null) return false;
            if (m.Body.HasExceptionHandlers) return false;
            if (m.Body.Instructions.Count < 2) return false;

            var ret = m.ReturnType;
            if (!IsAllowedSigType(ret) && !IsVoid(ret)) return false;
            foreach (var p in m.Parameters)
            {
                if (p.IsHiddenThisParameter) return false;
                if (!IsAllowedSigType(p.Type)) return false;
            }
            if (m.Body.HasVariables)
            {
                foreach (var v in m.Body.Variables)
                {
                    if (!IsAllowedSigType(v.Type)) return false;
                }
            }

            foreach (var inst in m.Body.Instructions)
            {
                if (!IsAllowedOpcode(inst)) return false;
            }
            return true;
        }

        private bool IsVoid(TypeSig t)
        {
            return t != null && t.FullName == "System.Void";
        }

        private bool IsAllowedSigType(TypeSig t)
        {
            if (t == null) return false;
            string fn = t.FullName;
            return fn == "System.String" || fn == "System.Object";
        }

        private bool IsAllowedOpcode(Instruction inst)
        {
            var op = inst.OpCode;
            if (op == DnOpCodes.Nop) return true;
            if (op == DnOpCodes.Ret) return true;
            if (op == DnOpCodes.Pop) return true;
            if (op == DnOpCodes.Dup) return true;
            if (op == DnOpCodes.Ldnull) return true;
            if (IsLdarg(op) || IsLdloc(op) || IsStloc(op)) return true;
            if (op == DnOpCodes.Ldstr) return true;
            if (op == DnOpCodes.Br || op == DnOpCodes.Br_S) return true;
            if (op == DnOpCodes.Brfalse || op == DnOpCodes.Brfalse_S) return true;
            if (op == DnOpCodes.Brtrue  || op == DnOpCodes.Brtrue_S)  return true;

            if (op == DnOpCodes.Call)     return CallTargetOK(inst);
            if (op == DnOpCodes.Callvirt) return CallTargetOK(inst);
            if (op == DnOpCodes.Newobj)   return CallTargetOK(inst);
            if (op == DnOpCodes.Castclass) return inst.Operand is ITypeDefOrRef;
            if (op == DnOpCodes.Isinst)    return inst.Operand is ITypeDefOrRef;
            return false;
        }

        private bool CallTargetOK(Instruction inst)
        {
            var mr = inst.Operand as IMethod;
            if (mr == null) return false;
            var sig = mr.MethodSig;
            if (sig == null) return false;
            if (sig.GenParamCount != 0) return false;

            if (!IsVoid(sig.RetType) && !IsAllowedSigType(sig.RetType)) return false;
            foreach (var p in sig.Params)
                if (!IsAllowedSigType(p)) return false;
            return true;
        }

        private bool IsLdarg(OpCode op)
        {
            return op == DnOpCodes.Ldarg || op == DnOpCodes.Ldarg_S
                || op == DnOpCodes.Ldarg_0 || op == DnOpCodes.Ldarg_1
                || op == DnOpCodes.Ldarg_2 || op == DnOpCodes.Ldarg_3;
        }

        private bool IsLdloc(OpCode op)
        {
            return op == DnOpCodes.Ldloc || op == DnOpCodes.Ldloc_S
                || op == DnOpCodes.Ldloc_0 || op == DnOpCodes.Ldloc_1
                || op == DnOpCodes.Ldloc_2 || op == DnOpCodes.Ldloc_3;
        }

        private bool IsStloc(OpCode op)
        {
            return op == DnOpCodes.Stloc || op == DnOpCodes.Stloc_S
                || op == DnOpCodes.Stloc_0 || op == DnOpCodes.Stloc_1
                || op == DnOpCodes.Stloc_2 || op == DnOpCodes.Stloc_3;
        }

        private int GetArgIndex(Instruction inst)
        {
            var op = inst.OpCode;
            if (op == DnOpCodes.Ldarg_0) return 0;
            if (op == DnOpCodes.Ldarg_1) return 1;
            if (op == DnOpCodes.Ldarg_2) return 2;
            if (op == DnOpCodes.Ldarg_3) return 3;
            var p = inst.Operand as Parameter;
            if (p != null) return p.Index;
            return Convert.ToInt32(inst.Operand);
        }

        private int GetLocalIndex(Instruction inst)
        {
            var op = inst.OpCode;
            if (op == DnOpCodes.Ldloc_0 || op == DnOpCodes.Stloc_0) return 0;
            if (op == DnOpCodes.Ldloc_1 || op == DnOpCodes.Stloc_1) return 1;
            if (op == DnOpCodes.Ldloc_2 || op == DnOpCodes.Stloc_2) return 2;
            if (op == DnOpCodes.Ldloc_3 || op == DnOpCodes.Stloc_3) return 3;
            var l = inst.Operand as Local;
            if (l != null) return l.Index;
            return Convert.ToInt32(inst.Operand);
        }

        private byte[] EmitBytecode(MethodDef method, int[] opcodeMap,
            List<string> stringPool, Dictionary<string, int> stringIndex,
            List<IMethod> methodPool, Dictionary<uint, int> methodIndex,
            List<ITypeDefOrRef> typePool, Dictionary<uint, int> typeIndex)
        {
            var bc = new List<byte>();
            var ipOfIl = new Dictionary<Instruction, int>();
            var pendingBranches = new List<KeyValuePair<int, Instruction>>();

            foreach (var inst in method.Body.Instructions)
            {
                ipOfIl[inst] = bc.Count;
                var op = inst.OpCode;

                if (op == DnOpCodes.Nop)
                {
                    bc.Add((byte)opcodeMap[VOP_NOP]);
                }
                else if (op == DnOpCodes.Ret)
                {
                    bc.Add((byte)opcodeMap[VOP_RET]);
                }
                else if (op == DnOpCodes.Pop)
                {
                    bc.Add((byte)opcodeMap[VOP_POP]);
                }
                else if (op == DnOpCodes.Dup)
                {
                    bc.Add((byte)opcodeMap[VOP_DUP]);
                }
                else if (op == DnOpCodes.Ldnull)
                {
                    bc.Add((byte)opcodeMap[VOP_LDNULL]);
                }
                else if (IsLdarg(op))
                {
                    int idx = GetArgIndex(inst);
                    if (idx < 0 || idx > 255) return null;
                    bc.Add((byte)opcodeMap[VOP_LDARG]);
                    bc.Add((byte)idx);
                }
                else if (IsLdloc(op))
                {
                    int idx = GetLocalIndex(inst);
                    if (idx < 0 || idx > 255) return null;
                    bc.Add((byte)opcodeMap[VOP_LDLOC]);
                    bc.Add((byte)idx);
                }
                else if (IsStloc(op))
                {
                    int idx = GetLocalIndex(inst);
                    if (idx < 0 || idx > 255) return null;
                    bc.Add((byte)opcodeMap[VOP_STLOC]);
                    bc.Add((byte)idx);
                }
                else if (op == DnOpCodes.Ldstr)
                {
                    string s = inst.Operand as string ?? "";
                    int sidx;
                    if (!stringIndex.TryGetValue(s, out sidx))
                    {
                        sidx = stringPool.Count;
                        stringPool.Add(s);
                        stringIndex[s] = sidx;
                    }
                    bc.Add((byte)opcodeMap[VOP_LDSTR]);
                    EmitInt32LE(bc, sidx);
                }
                else if (op == DnOpCodes.Br || op == DnOpCodes.Br_S)
                {
                    bc.Add((byte)opcodeMap[VOP_BR]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Brtrue || op == DnOpCodes.Brtrue_S)
                {
                    bc.Add((byte)opcodeMap[VOP_BRTRUE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Brfalse || op == DnOpCodes.Brfalse_S)
                {
                    bc.Add((byte)opcodeMap[VOP_BRFALSE]);
                    pendingBranches.Add(new KeyValuePair<int, Instruction>(bc.Count, (Instruction)inst.Operand));
                    EmitInt32LE(bc, 0);
                }
                else if (op == DnOpCodes.Call || op == DnOpCodes.Callvirt || op == DnOpCodes.Newobj)
                {
                    var mr = inst.Operand as IMethod;
                    if (mr == null) return null;
                    uint key = mr.MDToken.Raw;
                    int midx;
                    if (!methodIndex.TryGetValue(key, out midx))
                    {
                        midx = methodPool.Count;
                        methodPool.Add(mr);
                        methodIndex[key] = midx;
                    }
                    byte vop;
                    if (op == DnOpCodes.Call) vop = VOP_CALL;
                    else if (op == DnOpCodes.Callvirt) vop = VOP_CALLVIRT;
                    else vop = VOP_NEWOBJ;
                    bc.Add((byte)opcodeMap[vop]);
                    EmitInt32LE(bc, midx);
                }
                else if (op == DnOpCodes.Castclass)
                {
                    var tr = inst.Operand as ITypeDefOrRef;
                    if (tr == null) return null;
                    uint key = tr.MDToken.Raw;
                    int tidx;
                    if (!typeIndex.TryGetValue(key, out tidx))
                    {
                        tidx = typePool.Count;
                        typePool.Add(tr);
                        typeIndex[key] = tidx;
                    }
                    bc.Add((byte)opcodeMap[VOP_CASTCLASS]);
                    EmitInt32LE(bc, tidx);
                }
                else if (op == DnOpCodes.Isinst)
                {
                    var tr = inst.Operand as ITypeDefOrRef;
                    if (tr == null) return null;
                    uint key = tr.MDToken.Raw;
                    int tidx;
                    if (!typeIndex.TryGetValue(key, out tidx))
                    {
                        tidx = typePool.Count;
                        typePool.Add(tr);
                        typeIndex[key] = tidx;
                    }
                    bc.Add((byte)opcodeMap[VOP_ISINST]);
                    EmitInt32LE(bc, tidx);
                }
                else
                {
                    return null;
                }
            }

            foreach (var pb in pendingBranches)
            {
                var target = pb.Value;
                if (target == null || !ipOfIl.ContainsKey(target)) return null;
                int targetIp = ipOfIl[target];
                bc[pb.Key]     = (byte)(targetIp & 0xFF);
                bc[pb.Key + 1] = (byte)((targetIp >> 8) & 0xFF);
                bc[pb.Key + 2] = (byte)((targetIp >> 16) & 0xFF);
                bc[pb.Key + 3] = (byte)((targetIp >> 24) & 0xFF);
            }

            return bc.ToArray();
        }

        private void EmitInt32LE(List<byte> bc, int v)
        {
            bc.Add((byte)(v & 0xFF));
            bc.Add((byte)((v >> 8) & 0xFF));
            bc.Add((byte)((v >> 16) & 0xFF));
            bc.Add((byte)((v >> 24) & 0xFF));
        }

        private void EmitStub(ModuleDef module, MethodDef method, int slot, MethodDef dispatcher)
        {
            method.Body.Instructions.Clear();
            method.Body.Variables.Clear();
            method.Body.ExceptionHandlers.Clear();
            method.Body.InitLocals = true;

            var il = method.Body.Instructions;
            var objectTypeRef = module.CorLibTypes.Object.TypeDefOrRef;

            int numArgs = method.Parameters.Count;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, slot));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, numArgs));
            il.Add(Instruction.Create(DnOpCodes.Newarr, objectTypeRef));
            for (int i = 0; i < numArgs; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[i]));

                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }

            il.Add(Instruction.Create(DnOpCodes.Call, dispatcher));

            if (IsVoid(method.ReturnType))
            {
                il.Add(Instruction.Create(DnOpCodes.Pop));
                il.Add(Instruction.Create(DnOpCodes.Ret));
            }
            else
            {

                il.Add(Instruction.Create(DnOpCodes.Castclass, method.ReturnType.ToTypeDefOrRef()));
                il.Add(Instruction.Create(DnOpCodes.Ret));
            }
        }

        private MethodDef BuildDispatcher(ModuleDef module, TypeDef vmType,
            FieldDef fldCode, FieldDef fldKeys, FieldDef fldNumLocals,
            FieldDef fldStrings, FieldDef fldMethods, FieldDef fldTypes, int[] opcodeMap)
        {
            var int32 = module.CorLibTypes.Int32;
            var byteT = module.CorLibTypes.Byte;
            var objT  = module.CorLibTypes.Object;
            var stringT = module.CorLibTypes.String;

            var byteArr = new SZArraySig(byteT);
            var objArr  = new SZArraySig(objT);

            var sig = MethodSig.CreateStatic(objT, int32, objArr);
            var method = new MethodDefUser(engine.MakeName(), sig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;

            method.Body.Variables.Add(new Local(byteArr));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(objArr));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(objArr));
            method.Body.Variables.Add(new Local(int32));
            method.Body.Variables.Add(new Local(objT));
            method.Body.Variables.Add(new Local(objT));

            const int LOC_CODE = 0;
            const int LOC_KEY = 1;
            const int LOC_IP = 2;
            const int LOC_OP = 3;
            const int LOC_STACK = 4;
            const int LOC_SP = 5;
            const int LOC_LOCALS = 6;
            const int LOC_T1 = 7;
            const int LOC_O1 = 8;
            const int LOC_O2 = 9;

            const int ARG_SLOT = 0;
            const int ARG_ARGS = 1;

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, fldCode));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_SLOT]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_CODE]));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, fldKeys));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_SLOT]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_KEY]));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 256));
            il.Add(Instruction.Create(DnOpCodes.Newarr, objT.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_STACK]));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, fldNumLocals));
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_SLOT]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Newarr, objT.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_LOCALS]));

            var loopStart = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]);
            var loopEnd   = Instruction.Create(DnOpCodes.Nop);
            var advance1  = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]);

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Bge, loopEnd));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_KEY]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_OP]));

            var blkNop      = Instruction.Create(DnOpCodes.Nop);
            var blkRet      = Instruction.Create(DnOpCodes.Nop);
            var blkLdarg    = Instruction.Create(DnOpCodes.Nop);
            var blkLdloc    = Instruction.Create(DnOpCodes.Nop);
            var blkStloc    = Instruction.Create(DnOpCodes.Nop);
            var blkPop      = Instruction.Create(DnOpCodes.Nop);
            var blkDup      = Instruction.Create(DnOpCodes.Nop);
            var blkLdnull   = Instruction.Create(DnOpCodes.Nop);
            var blkLdstr    = Instruction.Create(DnOpCodes.Nop);
            var blkBr       = Instruction.Create(DnOpCodes.Nop);
            var blkBrtrue   = Instruction.Create(DnOpCodes.Nop);
            var blkBrfalse  = Instruction.Create(DnOpCodes.Nop);
            var blkCall     = Instruction.Create(DnOpCodes.Nop);
            var blkCallvirt = Instruction.Create(DnOpCodes.Nop);
            var blkNewobj   = Instruction.Create(DnOpCodes.Nop);
            var blkCastclass = Instruction.Create(DnOpCodes.Nop);
            var blkIsinst    = Instruction.Create(DnOpCodes.Nop);

            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_NOP],     blkNop);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_RET],     blkRet);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_LDARG],   blkLdarg);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_LDLOC],   blkLdloc);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_STLOC],   blkStloc);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_POP],     blkPop);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_DUP],     blkDup);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_LDNULL],  blkLdnull);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_LDSTR],   blkLdstr);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_BR],      blkBr);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_BRTRUE],  blkBrtrue);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_BRFALSE], blkBrfalse);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CALL],    blkCall);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CALLVIRT], blkCallvirt);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_NEWOBJ],   blkNewobj);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_CASTCLASS], blkCastclass);
            EmitDispatchEntry(il, method.Body.Variables[LOC_OP], opcodeMap[VOP_ISINST],    blkIsinst);

            il.Add(Instruction.Create(DnOpCodes.Br, advance1));

            il.Add(blkNop);
            il.Add(Instruction.Create(DnOpCodes.Br, advance1));

            il.Add(blkRet);
            il.Add(Instruction.Create(DnOpCodes.Br, loopEnd));

            il.Add(blkLdarg);
            EmitReadByteAtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[ARG_ARGS]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O1]));
            EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O1);
            EmitAdvanceIp(il, method, LOC_IP, 2, loopStart);

            il.Add(blkLdloc);
            EmitReadByteAtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_LOCALS]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O1]));
            EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O1);
            EmitAdvanceIp(il, method, LOC_IP, 2, loopStart);

            il.Add(blkStloc);
            EmitReadByteAtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            EmitObjPop(il, method, LOC_STACK, LOC_SP, LOC_O1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_LOCALS]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            EmitAdvanceIp(il, method, LOC_IP, 2, loopStart);

            il.Add(blkPop);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Br, advance1));

            il.Add(blkDup);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O1]));
            EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O1);
            il.Add(Instruction.Create(DnOpCodes.Br, advance1));

            il.Add(blkLdnull);
            il.Add(Instruction.Create(DnOpCodes.Ldnull));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O1]));
            EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O1);
            il.Add(Instruction.Create(DnOpCodes.Br, advance1));

            il.Add(blkLdstr);
            EmitReadInt32AtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, fldStrings));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O1]));
            EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O1);
            EmitAdvanceIp(il, method, LOC_IP, 5, loopStart);

            il.Add(blkBr);
            EmitReadInt32AtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(blkBrtrue);
            EmitObjPop(il, method, LOC_STACK, LOC_SP, LOC_O1);
            EmitReadInt32AtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            var brtNotTaken = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]);
            il.Add(Instruction.Create(DnOpCodes.Brfalse, brtNotTaken));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));
            il.Add(brtNotTaken);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 5));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(blkBrfalse);
            EmitObjPop(il, method, LOC_STACK, LOC_SP, LOC_O1);
            EmitReadInt32AtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            var brfNotTaken = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]);
            il.Add(Instruction.Create(DnOpCodes.Brtrue, brfNotTaken));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));
            il.Add(brfNotTaken);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 5));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            EmitCallBlock(il, method, blkCall, fldMethods, LOC_STACK, LOC_SP, LOC_T1, LOC_O1, LOC_O2, false, loopStart, LOC_CODE, LOC_IP, LOC_KEY, module);

            EmitCallBlock(il, method, blkCallvirt, fldMethods, LOC_STACK, LOC_SP, LOC_T1, LOC_O1, LOC_O2, true, loopStart, LOC_CODE, LOC_IP, LOC_KEY, module);

            EmitNewobjBlock(il, method, blkNewobj, fldMethods, LOC_STACK, LOC_SP, LOC_T1, LOC_O1, LOC_O2, loopStart, LOC_CODE, LOC_IP, LOC_KEY, module);

            il.Add(blkCastclass);
            EmitReadInt32AtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            EmitObjPop(il, method, LOC_STACK, LOC_SP, LOC_O1);
            EmitResolveTypeFromTokens(il, method, fldTypes, LOC_T1, LOC_O2, module);

            EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O1);
            EmitAdvanceIp(il, method, LOC_IP, 5, loopStart);

            il.Add(blkIsinst);
            EmitReadInt32AtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);
            EmitObjPop(il, method, LOC_STACK, LOC_SP, LOC_O1);
            EmitResolveTypeFromTokens(il, method, fldTypes, LOC_T1, LOC_O2, module);

            {
                var typeIsInst = module.Import(typeof(Type).GetMethod("IsInstanceOfType", new[] { typeof(object) }));
                var pushNull = Instruction.Create(DnOpCodes.Ldnull);
                var afterPush = Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O1]);
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O2]));
                il.Add(Instruction.Create(DnOpCodes.Castclass, module.Import(typeof(Type))));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
                il.Add(Instruction.Create(DnOpCodes.Callvirt, typeIsInst));
                il.Add(Instruction.Create(DnOpCodes.Brfalse, pushNull));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
                il.Add(Instruction.Create(DnOpCodes.Br, afterPush));
                il.Add(pushNull);
                il.Add(afterPush);
                EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O1);
            }
            EmitAdvanceIp(il, method, LOC_IP, 5, loopStart);

            il.Add(advance1);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(loopEnd);
            var emptyStack = Instruction.Create(DnOpCodes.Ldnull);
            var afterRet = Instruction.Create(DnOpCodes.Ret);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ble, emptyStack));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Br, afterRet));
            il.Add(emptyStack);
            il.Add(afterRet);

            return method;
        }

        private void EmitDispatchEntry(IList<Instruction> il, Local opLocal, int opcodeValue, Instruction target)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldloc, opLocal));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, opcodeValue));
            il.Add(Instruction.Create(DnOpCodes.Beq, target));
        }

        private void EmitObjPush(IList<Instruction> il, MethodDef method, int LOC_STACK, int LOC_SP, int LOC_VAL)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_VAL]));
            il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
        }

        private void EmitObjPop(IList<Instruction> il, MethodDef method, int LOC_STACK, int LOC_SP, int LOC_DEST)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST]));
        }

        private void EmitReadByteAtIpPlus(IList<Instruction> il, MethodDef method,
            int LOC_CODE, int LOC_IP, int LOC_KEY, int offset, int LOC_DEST)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, offset));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_KEY]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, offset));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST]));
        }

        private void EmitReadInt32AtIpPlus(IList<Instruction> il, MethodDef method,
            int LOC_CODE, int LOC_IP, int LOC_KEY, int offset, int LOC_DEST)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST]));
            for (int i = 0; i < 4; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_DEST]));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_CODE]));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, offset + i));
                il.Add(Instruction.Create(DnOpCodes.Add));
                il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_KEY]));
                il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, offset + i));
                il.Add(Instruction.Create(DnOpCodes.Add));
                il.Add(Instruction.Create(DnOpCodes.Xor));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
                il.Add(Instruction.Create(DnOpCodes.And));
                il.Add(Instruction.Create(DnOpCodes.Xor));
                if (i > 0)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i * 8));
                    il.Add(Instruction.Create(DnOpCodes.Shl));
                }
                il.Add(Instruction.Create(DnOpCodes.Or));
                il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST]));
            }
        }

        private void EmitAdvanceIp(IList<Instruction> il, MethodDef method,
            int LOC_IP, int delta, Instruction loopStart)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, delta));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_IP]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));
        }

        private void EmitResolveMethodFromTokens(IList<Instruction> il, MethodDef method,
            FieldDef fldMethods, int LOC_IDX, int LOC_DEST_OBJ, ModuleDef mod)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, fldMethods));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IDX]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST_OBJ]));
        }

        private void EmitResolveTypeFromTokens(IList<Instruction> il, MethodDef method,
            FieldDef fldTypes, int LOC_IDX, int LOC_DEST_OBJ, ModuleDef mod)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, fldTypes));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_IDX]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_DEST_OBJ]));
        }

        private void EmitCallBlock(IList<Instruction> il, MethodDef method, Instruction blkStart,
            FieldDef fldMethods, int LOC_STACK, int LOC_SP, int LOC_T1, int LOC_O1, int LOC_O2,
            bool isVirtual, Instruction loopStart, int LOC_CODE, int LOC_IP, int LOC_KEY,
            ModuleDef mod)
        {
            var methodBaseType = mod.Import(typeof(MethodBase));
            var methodInfoType = mod.Import(typeof(MethodInfo));
            var getParams      = mod.Import(typeof(MethodBase).GetMethod("GetParameters", Type.EmptyTypes));
            var invokeMethod   = mod.Import(typeof(MethodBase).GetMethod("Invoke", new[] { typeof(object), typeof(object[]) }));
            var isStaticGet    = mod.Import(typeof(MethodBase).GetProperty("IsStatic").GetGetMethod());
            var returnTypeGet  = mod.Import(typeof(MethodInfo).GetProperty("ReturnType").GetGetMethod());
            var fullNameGet    = mod.Import(typeof(Type).GetProperty("FullName").GetGetMethod());
            var stringEquality = mod.Import(typeof(string).GetMethod("op_Equality", new[] { typeof(string), typeof(string) }));

            il.Add(blkStart);

            EmitReadInt32AtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);

            EmitResolveMethodFromTokens(il, method, fldMethods, LOC_T1, LOC_O1, mod);

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            il.Add(Instruction.Create(DnOpCodes.Castclass, methodBaseType));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getParams));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Newarr, mod.CorLibTypes.Object.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O2]));

            var fillStart = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]);
            var fillEnd   = Instruction.Create(DnOpCodes.Nop);

            il.Add(fillStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ble, fillEnd));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O2]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));

            il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Br, fillStart));
            il.Add(fillEnd);

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            il.Add(Instruction.Create(DnOpCodes.Castclass, methodBaseType));

            var pushNullTarget = Instruction.Create(DnOpCodes.Ldnull);
            var afterTarget    = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O2]);

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            il.Add(Instruction.Create(DnOpCodes.Castclass, methodBaseType));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, isStaticGet));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, pushNullTarget));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Br, afterTarget));

            il.Add(pushNullTarget);

            il.Add(afterTarget);

            il.Add(Instruction.Create(DnOpCodes.Callvirt, invokeMethod));

            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O2]));

            var voidCase    = Instruction.Create(DnOpCodes.Nop);
            var afterReturn = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            il.Add(Instruction.Create(DnOpCodes.Isinst, methodInfoType));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, voidCase));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            il.Add(Instruction.Create(DnOpCodes.Castclass, methodInfoType));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, returnTypeGet));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, fullNameGet));
            il.Add(Instruction.Create(DnOpCodes.Ldstr, "System.Void"));
            il.Add(Instruction.Create(DnOpCodes.Call, stringEquality));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, voidCase));

            EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O2);
            il.Add(Instruction.Create(DnOpCodes.Br, afterReturn));

            il.Add(voidCase);

            il.Add(afterReturn);

            EmitAdvanceIp(il, method, LOC_IP, 5, loopStart);
        }

        private void EmitNewobjBlock(IList<Instruction> il, MethodDef method, Instruction blkStart,
            FieldDef fldMethods, int LOC_STACK, int LOC_SP, int LOC_T1, int LOC_O1, int LOC_O2,
            Instruction loopStart, int LOC_CODE, int LOC_IP, int LOC_KEY, ModuleDef mod)
        {
            var methodBaseType = mod.Import(typeof(MethodBase));
            var ctorInfoType   = mod.Import(typeof(ConstructorInfo));
            var getParams      = mod.Import(typeof(MethodBase).GetMethod("GetParameters", Type.EmptyTypes));
            var ctorInvoke     = mod.Import(typeof(ConstructorInfo).GetMethod("Invoke", new[] { typeof(object[]) }));

            il.Add(blkStart);

            EmitReadInt32AtIpPlus(il, method, LOC_CODE, LOC_IP, LOC_KEY, 1, LOC_T1);

            EmitResolveMethodFromTokens(il, method, fldMethods, LOC_T1, LOC_O1, mod);

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            il.Add(Instruction.Create(DnOpCodes.Castclass, methodBaseType));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getParams));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Newarr, mod.CorLibTypes.Object.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O2]));

            var fillStart = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]);
            var fillEnd   = Instruction.Create(DnOpCodes.Nop);

            il.Add(fillStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ble, fillEnd));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_T1]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O2]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_T1]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_STACK]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_SP]));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Br, fillStart));
            il.Add(fillEnd);

            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O1]));
            il.Add(Instruction.Create(DnOpCodes.Castclass, ctorInfoType));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[LOC_O2]));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, ctorInvoke));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[LOC_O2]));

            EmitObjPush(il, method, LOC_STACK, LOC_SP, LOC_O2);

            EmitAdvanceIp(il, method, LOC_IP, 5, loopStart);
        }

        private MethodDef BuildInit(ModuleDef module, TypeDef vmType,
            FieldDef fldCode, FieldDef fldKeys, FieldDef fldNumLocals,
            FieldDef fldStrings, FieldDef fldMethods, FieldDef fldTypes,
            List<byte[]> codes, List<byte> keys, List<byte> numLocals,
            List<string> strings, List<IMethod> methodImports,
            List<ITypeDefOrRef> typeImports)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            var il = method.Body.Instructions;

            int n = codes.Count;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, n));
            il.Add(Instruction.Create(DnOpCodes.Newarr, new TypeSpecUser(new SZArraySig(module.CorLibTypes.Byte))));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fldCode));
            for (int i = 0; i < n; i++)
            {
                var bc = codes[i];
                il.Add(Instruction.Create(DnOpCodes.Ldsfld, fldCode));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, bc.Length));
                il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
                for (int b = 0; b < bc.Length; b++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Dup));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)bc[b]));
                    il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
                }
                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, n));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            for (int i = 0; i < n; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)keys[i]));
                il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
            }
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fldKeys));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, n));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            for (int i = 0; i < n; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)numLocals[i]));
                il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
            }
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fldNumLocals));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, strings.Count));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.String.TypeDefOrRef));
            for (int i = 0; i < strings.Count; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldstr, strings[i]));
                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fldStrings));

            var methodBaseTypeRef    = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase");
            var typeTypeRef          = module.CorLibTypes.GetTypeRef("System", "Type");
            var getMethodFromHandle  = module.Import(typeof(MethodBase).GetMethod(
                "GetMethodFromHandle", new[] { typeof(RuntimeMethodHandle) }));
            var getTypeFromHandle    = module.Import(typeof(Type).GetMethod(
                "GetTypeFromHandle", new[] { typeof(RuntimeTypeHandle) }));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, methodImports.Count));
            il.Add(Instruction.Create(DnOpCodes.Newarr, methodBaseTypeRef));
            for (int i = 0; i < methodImports.Count; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldtoken, methodImports[i]));
                il.Add(Instruction.Create(DnOpCodes.Call, getMethodFromHandle));
                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fldMethods));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, typeImports.Count));
            il.Add(Instruction.Create(DnOpCodes.Newarr, typeTypeRef));
            for (int i = 0; i < typeImports.Count; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldtoken, typeImports[i]));
                il.Add(Instruction.Create(DnOpCodes.Call, getTypeFromHandle));
                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fldTypes));

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

