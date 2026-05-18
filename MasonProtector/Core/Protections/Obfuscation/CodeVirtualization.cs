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
    internal class CodeVirtualizationProtection
    {
        private Obfuscation engine;
        private Random rng;

        private TypeDefUser vmDispatcherType;
        private TypeDefUser vmHandlerType;
        private TypeDefUser vmStateType;
        private TypeDefUser vmOpcodeType;
        private TypeDefUser vmStackType;
        private TypeDefUser vmMemoryType;

        internal CodeVirtualizationProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyCodeVirtualization(ModuleDef module, TypeDef modType)
        {
            CreateVMDispatcherType(module);
            CreateVMHandlerType(module);
            CreateVMStateType(module);
            CreateVMOpcodeType(module);
            CreateVMStackType(module);
            CreateVMMemoryType(module);

            module.Types.Add(vmDispatcherType);
            module.Types.Add(vmHandlerType);
            module.Types.Add(vmStateType);
            module.Types.Add(vmOpcodeType);
            module.Types.Add(vmStackType);
            module.Types.Add(vmMemoryType);

            engine.injectedTypes.Add(vmDispatcherType);
            engine.injectedTypes.Add(vmHandlerType);
            engine.injectedTypes.Add(vmStateType);
            engine.injectedTypes.Add(vmOpcodeType);
            engine.injectedTypes.Add(vmStackType);
            engine.injectedTypes.Add(vmMemoryType);

            BuildInitializer(module, modType);
        }

        private void CreateVMDispatcherType(ModuleDef module)
        {
            vmDispatcherType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmDispatcherType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

            var dispatchTableField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmDispatcherType.Fields.Add(dispatchTableField);

            var stateCounterField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmDispatcherType.Fields.Add(stateCounterField);

            var opcodeTableField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmDispatcherType.Fields.Add(opcodeTableField);

            var handlerIndexField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmDispatcherType.Fields.Add(handlerIndexField);

            var cycleCountField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int64),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmDispatcherType.Fields.Add(cycleCountField);

            var dispatchFlagsField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmDispatcherType.Fields.Add(dispatchFlagsField);

            var lookupCacheField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmDispatcherType.Fields.Add(lookupCacheField);

            var entryPointField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmDispatcherType.Fields.Add(entryPointField);

            var runDispatch = BuildDispatchRunMethod(module, dispatchTableField, stateCounterField, opcodeTableField, handlerIndexField, cycleCountField);
            vmDispatcherType.Methods.Add(runDispatch);
            engine.injectedMethods.Add(runDispatch);

            var resolveHandler = BuildResolveHandlerMethod(module, dispatchTableField, handlerIndexField, lookupCacheField);
            vmDispatcherType.Methods.Add(resolveHandler);
            engine.injectedMethods.Add(resolveHandler);

            var fetchOpcode = BuildFetchOpcodeMethod(module, opcodeTableField, stateCounterField);
            vmDispatcherType.Methods.Add(fetchOpcode);
            engine.injectedMethods.Add(fetchOpcode);

            var resetDispatch = BuildResetDispatchMethod(module, stateCounterField, handlerIndexField, cycleCountField, dispatchFlagsField);
            vmDispatcherType.Methods.Add(resetDispatch);
            engine.injectedMethods.Add(resetDispatch);

            var validateState = BuildValidateStateMethod(module, stateCounterField, dispatchFlagsField, entryPointField);
            vmDispatcherType.Methods.Add(validateState);
            engine.injectedMethods.Add(validateState);

            var initDispatch = BuildInitDispatchMethod(module, dispatchTableField, opcodeTableField, lookupCacheField, entryPointField);
            vmDispatcherType.Methods.Add(initDispatch);
            engine.injectedMethods.Add(initDispatch);
        }

        private void CreateVMHandlerType(ModuleDef module)
        {
            vmHandlerType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmHandlerType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

            var handlerTableField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmHandlerType.Fields.Add(handlerTableField);

            var activeHandlerField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmHandlerType.Fields.Add(activeHandlerField);

            var handlerResultField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmHandlerType.Fields.Add(handlerResultField);

            var handlerCountField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmHandlerType.Fields.Add(handlerCountField);

            var exceptionFlagField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Boolean),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmHandlerType.Fields.Add(exceptionFlagField);

            var handlerContextField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmHandlerType.Fields.Add(handlerContextField);

            var dispatchSwitch = BuildHandlerDispatchMethod(module, handlerTableField, activeHandlerField, handlerResultField, handlerCountField);
            vmHandlerType.Methods.Add(dispatchSwitch);
            engine.injectedMethods.Add(dispatchSwitch);

            var executeHandler = BuildExecuteHandlerMethod(module, activeHandlerField, handlerResultField, exceptionFlagField);
            vmHandlerType.Methods.Add(executeHandler);
            engine.injectedMethods.Add(executeHandler);

            var registerHandler = BuildRegisterHandlerMethod(module, handlerTableField, handlerCountField, handlerContextField);
            vmHandlerType.Methods.Add(registerHandler);
            engine.injectedMethods.Add(registerHandler);

            var lookupHandler = BuildLookupHandlerMethod(module, handlerTableField, handlerCountField);
            vmHandlerType.Methods.Add(lookupHandler);
            engine.injectedMethods.Add(lookupHandler);

            var clearHandlers = BuildClearHandlersMethod(module, handlerTableField, handlerCountField, activeHandlerField, exceptionFlagField);
            vmHandlerType.Methods.Add(clearHandlers);
            engine.injectedMethods.Add(clearHandlers);
        }

        private void CreateVMStateType(ModuleDef module)
        {
            vmStateType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmStateType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

            var stackPointerField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmStateType.Fields.Add(stackPointerField);

            var instructionPointerField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmStateType.Fields.Add(instructionPointerField);

            var flagRegisterField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStateType.Fields.Add(flagRegisterField);

            var registerAField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStateType.Fields.Add(registerAField);

            var registerBField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStateType.Fields.Add(registerBField);

            var registerCField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int64),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStateType.Fields.Add(registerCField);

            var haltFlagField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Boolean),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmStateType.Fields.Add(haltFlagField);

            var overflowFlagField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Boolean),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStateType.Fields.Add(overflowFlagField);

            var advanceIP = BuildAdvanceIPMethod(module, instructionPointerField, haltFlagField, flagRegisterField);
            vmStateType.Methods.Add(advanceIP);
            engine.injectedMethods.Add(advanceIP);

            var setFlags = BuildSetFlagsMethod(module, flagRegisterField, overflowFlagField, registerAField, registerBField);
            vmStateType.Methods.Add(setFlags);
            engine.injectedMethods.Add(setFlags);

            var resetState = BuildResetStateMethod(module, stackPointerField, instructionPointerField, flagRegisterField,
                registerAField, registerBField, registerCField, haltFlagField, overflowFlagField);
            vmStateType.Methods.Add(resetState);
            engine.injectedMethods.Add(resetState);

            var loadRegisters = BuildLoadRegistersMethod(module, registerAField, registerBField, registerCField, flagRegisterField);
            vmStateType.Methods.Add(loadRegisters);
            engine.injectedMethods.Add(loadRegisters);

            var storeRegisters = BuildStoreRegistersMethod(module, registerAField, registerBField, registerCField);
            vmStateType.Methods.Add(storeRegisters);
            engine.injectedMethods.Add(storeRegisters);

            var checkHalt = BuildCheckHaltMethod(module, haltFlagField, instructionPointerField, flagRegisterField);
            vmStateType.Methods.Add(checkHalt);
            engine.injectedMethods.Add(checkHalt);
        }

        private void CreateVMOpcodeType(ModuleDef module)
        {
            vmOpcodeType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmOpcodeType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

            var opcodeResultField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmOpcodeType.Fields.Add(opcodeResultField);

            var opcodeOperandField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmOpcodeType.Fields.Add(opcodeOperandField);

            var opcodeTypeField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Byte),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmOpcodeType.Fields.Add(opcodeTypeField);

            var opcodeAccField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int64),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmOpcodeType.Fields.Add(opcodeAccField);

            var opcodeCarryField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Boolean),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmOpcodeType.Fields.Add(opcodeCarryField);

            var opcodeFlagsField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmOpcodeType.Fields.Add(opcodeFlagsField);

            var opcodeAdd = BuildOpcodeAddMethod(module, opcodeResultField, opcodeOperandField, opcodeCarryField);
            vmOpcodeType.Methods.Add(opcodeAdd);
            engine.injectedMethods.Add(opcodeAdd);

            var opcodeSub = BuildOpcodeSubMethod(module, opcodeResultField, opcodeOperandField, opcodeCarryField);
            vmOpcodeType.Methods.Add(opcodeSub);
            engine.injectedMethods.Add(opcodeSub);

            var opcodeXor = BuildOpcodeXorMethod(module, opcodeResultField, opcodeOperandField, opcodeFlagsField);
            vmOpcodeType.Methods.Add(opcodeXor);
            engine.injectedMethods.Add(opcodeXor);

            var opcodeLoad = BuildOpcodeLoadMethod(module, opcodeResultField, opcodeAccField, opcodeTypeField);
            vmOpcodeType.Methods.Add(opcodeLoad);
            engine.injectedMethods.Add(opcodeLoad);

            var opcodeStore = BuildOpcodeStoreMethod(module, opcodeResultField, opcodeAccField, opcodeOperandField);
            vmOpcodeType.Methods.Add(opcodeStore);
            engine.injectedMethods.Add(opcodeStore);

            var opcodeBranch = BuildOpcodeBranchMethod(module, opcodeResultField, opcodeFlagsField, opcodeOperandField);
            vmOpcodeType.Methods.Add(opcodeBranch);
            engine.injectedMethods.Add(opcodeBranch);

            var opcodeCompare = BuildOpcodeCompareMethod(module, opcodeResultField, opcodeOperandField, opcodeFlagsField, opcodeCarryField);
            vmOpcodeType.Methods.Add(opcodeCompare);
            engine.injectedMethods.Add(opcodeCompare);

            var opcodeNot = BuildOpcodeNotMethod(module, opcodeResultField, opcodeOperandField, opcodeFlagsField);
            vmOpcodeType.Methods.Add(opcodeNot);
            engine.injectedMethods.Add(opcodeNot);
        }

        private void CreateVMStackType(ModuleDef module)
        {
            vmStackType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmStackType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

            var stackDataField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStackType.Fields.Add(stackDataField);

            var stackTopField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStackType.Fields.Add(stackTopField);

            var stackCapacityField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStackType.Fields.Add(stackCapacityField);

            var stackOverflowField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Boolean),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmStackType.Fields.Add(stackOverflowField);

            var stackFrameBaseField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStackType.Fields.Add(stackFrameBaseField);

            var stackHashField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmStackType.Fields.Add(stackHashField);

            var pushMethod = BuildStackPushMethod(module, stackDataField, stackTopField, stackCapacityField, stackOverflowField);
            vmStackType.Methods.Add(pushMethod);
            engine.injectedMethods.Add(pushMethod);

            var popMethod = BuildStackPopMethod(module, stackDataField, stackTopField, stackOverflowField);
            vmStackType.Methods.Add(popMethod);
            engine.injectedMethods.Add(popMethod);

            var peekMethod = BuildStackPeekMethod(module, stackDataField, stackTopField);
            vmStackType.Methods.Add(peekMethod);
            engine.injectedMethods.Add(peekMethod);

            var initStack = BuildInitStackMethod(module, stackDataField, stackTopField, stackCapacityField, stackOverflowField, stackFrameBaseField, stackHashField);
            vmStackType.Methods.Add(initStack);
            engine.injectedMethods.Add(initStack);

            var stackDepth = BuildStackDepthMethod(module, stackTopField, stackFrameBaseField);
            vmStackType.Methods.Add(stackDepth);
            engine.injectedMethods.Add(stackDepth);
        }

        private void CreateVMMemoryType(ModuleDef module)
        {
            vmMemoryType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmMemoryType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

            var memoryDataField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmMemoryType.Fields.Add(memoryDataField);

            var memorySizeField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmMemoryType.Fields.Add(memorySizeField);

            var memoryBaseField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmMemoryType.Fields.Add(memoryBaseField);

            var memoryProtectField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Boolean),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmMemoryType.Fields.Add(memoryProtectField);

            var memoryChecksumField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmMemoryType.Fields.Add(memoryChecksumField);

            var memoryAllocCountField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmMemoryType.Fields.Add(memoryAllocCountField);

            var memoryPageTableField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Int32)),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            vmMemoryType.Fields.Add(memoryPageTableField);

            var readMem = BuildMemoryReadMethod(module, memoryDataField, memorySizeField, memoryBaseField, memoryProtectField);
            vmMemoryType.Methods.Add(readMem);
            engine.injectedMethods.Add(readMem);

            var writeMem = BuildMemoryWriteMethod(module, memoryDataField, memorySizeField, memoryBaseField, memoryProtectField, memoryChecksumField);
            vmMemoryType.Methods.Add(writeMem);
            engine.injectedMethods.Add(writeMem);

            var allocMem = BuildMemoryAllocMethod(module, memoryDataField, memorySizeField, memoryAllocCountField, memoryPageTableField);
            vmMemoryType.Methods.Add(allocMem);
            engine.injectedMethods.Add(allocMem);

            var checksumMem = BuildMemoryChecksumMethod(module, memoryDataField, memorySizeField, memoryChecksumField);
            vmMemoryType.Methods.Add(checksumMem);
            engine.injectedMethods.Add(checksumMem);

            var initMem = BuildInitMemoryMethod(module, memoryDataField, memorySizeField, memoryBaseField,
                memoryProtectField, memoryChecksumField, memoryAllocCountField, memoryPageTableField);
            vmMemoryType.Methods.Add(initMem);
            engine.injectedMethods.Add(initMem);
        }

        private void BuildInitializer(ModuleDef module, TypeDef modType)
        {
            var initMethod = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            initMethod.Body = new CilBody();
            initMethod.Body.InitLocals = true;
            initMethod.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = initMethod.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(100, 9999)));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 255)));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            vmDispatcherType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);
            engine.InjectCallInCctor(module, modType, initMethod);
        }

        private MethodDef BuildDispatchRunMethod(ModuleDef module, FieldDef dispatchTable, FieldDef stateCounter,
            FieldDef opcodeTable, FieldDef handlerIndex, FieldDef cycleCount)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            var loopHead = Instruction.Create(DnOpCodes.Ldloc_2);
            il.Add(loopHead);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(32, 128)));
            il.Add(Instruction.Create(DnOpCodes.Bge, retLabel));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(2, 16)));
            il.Add(Instruction.Create(DnOpCodes.Rem));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var branch0 = Instruction.Create(DnOpCodes.Ldloc_0);
            var branch1 = Instruction.Create(DnOpCodes.Ldloc_1);
            var branchEnd = Instruction.Create(DnOpCodes.Ldloc_2);

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Beq, branch0));
            il.Add(Instruction.Create(DnOpCodes.Br, branch1));

            il.Add(branch0);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(100, 5000)));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, branchEnd));

            il.Add(branch1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Br, branchEnd));

            il.Add(branchEnd);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Br, loopHead));

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildResolveHandlerMethod(ModuleDef module, FieldDef dispatchTable, FieldDef handlerIndex, FieldDef lookupCache)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 255)));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var skipLabel = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Bgt, skipLabel));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(skipLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildFetchOpcodeMethod(ModuleDef module, FieldDef opcodeTable, FieldDef stateCounter)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ldloc_2);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(3, 32)));
            il.Add(Instruction.Create(DnOpCodes.Rem));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 255)));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            var midBranch = Instruction.Create(DnOpCodes.Ldloc_2);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(50, 200)));
            il.Add(Instruction.Create(DnOpCodes.Bgt, midBranch));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
            il.Add(Instruction.Create(DnOpCodes.Mul));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(midBranch);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 50)));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildResetDispatchMethod(ModuleDef module, FieldDef stateCounter, FieldDef handlerIndex,
            FieldDef cycleCount, FieldDef dispatchFlags)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stateCounter));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, handlerIndex));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, cycleCount));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, dispatchFlags));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildValidateStateMethod(ModuleDef module, FieldDef stateCounter, FieldDef dispatchFlags, FieldDef entryPoint)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

            var il = method.Body.Instructions;
            var retTrue = Instruction.Create(DnOpCodes.Ldc_I4_1);
            var retFalse = Instruction.Create(DnOpCodes.Ldc_I4_0);
            var retInst = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stateCounter));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Blt, retFalse));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, dispatchFlags));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 128)));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Beq, retTrue));
            il.Add(Instruction.Create(DnOpCodes.Br, retFalse));

            il.Add(retTrue);
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Br, retInst));

            il.Add(retFalse);
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(retInst);

            return method;
        }

        private MethodDef BuildInitDispatchMethod(ModuleDef module, FieldDef dispatchTable, FieldDef opcodeTable,
            FieldDef lookupCache, FieldDef entryPoint)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            int tableSize = rng.Next(192, 768);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, tableSize));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, dispatchTable));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, tableSize));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, opcodeTable));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, tableSize / 2));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, lookupCache));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, entryPoint));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var loopStart = Instruction.Create(DnOpCodes.Ldloc_0);
            var loopEnd = Instruction.Create(DnOpCodes.Ret);
            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, tableSize));
            il.Add(Instruction.Create(DnOpCodes.Bge, loopEnd));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, dispatchTable));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 255)));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I4));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(loopEnd);

            return method;
        }

        private MethodDef BuildHandlerDispatchMethod(ModuleDef module, FieldDef handlerTable, FieldDef activeHandler,
            FieldDef handlerResult, FieldDef handlerCount)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ldloc_2);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            var case0 = Instruction.Create(DnOpCodes.Ldloc_0);
            var case1 = Instruction.Create(DnOpCodes.Ldloc_0);
            var case2 = Instruction.Create(DnOpCodes.Ldloc_0);
            var caseDefault = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Beq, case0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Beq, case1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
            il.Add(Instruction.Create(DnOpCodes.Beq, case2));
            il.Add(Instruction.Create(DnOpCodes.Br, caseDefault));

            il.Add(case0);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(100, 9999)));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(case1);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 32)));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(case2);
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(caseDefault);
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildExecuteHandlerMethod(ModuleDef module, FieldDef activeHandler, FieldDef handlerResult, FieldDef exceptionFlag)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Ldarg_0);
            var tryEnd = Instruction.Create(DnOpCodes.Nop);
            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            var handlerEnd = Instruction.Create(DnOpCodes.Ret);

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 255)));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, handlerResult));
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));

            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, exceptionFlag));
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));

            il.Add(tryEnd);
            il.Add(handlerEnd);

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = tryEnd,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return method;
        }

        private MethodDef BuildRegisterHandlerMethod(ModuleDef module, FieldDef handlerTable, FieldDef handlerCount, FieldDef handlerContext)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, handlerCount));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, handlerCount));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, handlerCount));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildLookupHandlerMethod(ModuleDef module, FieldDef handlerTable, FieldDef handlerCount)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ldloc_1);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var loopStart = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, handlerCount));
            il.Add(Instruction.Create(DnOpCodes.Bge, retLabel));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));

            var notFound = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Bne_Un, notFound));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(notFound);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildClearHandlersMethod(ModuleDef module, FieldDef handlerTable, FieldDef handlerCount,
            FieldDef activeHandler, FieldDef exceptionFlag)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, handlerCount));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, activeHandler));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, exceptionFlag));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildAdvanceIPMethod(ModuleDef module, FieldDef ip, FieldDef haltFlag, FieldDef flagReg)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, ip));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var noHalt = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Bge, noHalt));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, haltFlag));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(noHalt);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, ip));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, flagReg));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 64)));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, flagReg));

            il.Add(retLabel);

            return method;
        }

        private MethodDef BuildSetFlagsMethod(ModuleDef module, FieldDef flagReg, FieldDef overflowFlag,
            FieldDef regA, FieldDef regB)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var noOverflow = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Bge, noOverflow));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, overflowFlag));

            il.Add(noOverflow);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, flagReg));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildResetStateMethod(ModuleDef module, FieldDef sp, FieldDef ip, FieldDef flags,
            FieldDef regA, FieldDef regB, FieldDef regC, FieldDef halt, FieldDef overflow)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, sp));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, ip));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, flags));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, regA));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, regB));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, regC));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, halt));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, overflow));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildLoadRegistersMethod(ModuleDef module, FieldDef regA, FieldDef regB, FieldDef regC, FieldDef flags)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ldloc_0);

            var loadB = Instruction.Create(DnOpCodes.Ldsfld, regB);
            var loadDefault = Instruction.Create(DnOpCodes.Ldsfld, flags);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            var loadA = Instruction.Create(DnOpCodes.Ldsfld, regA);
            il.Add(Instruction.Create(DnOpCodes.Beq, loadA));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Beq, loadB));
            il.Add(Instruction.Create(DnOpCodes.Br, loadDefault));

            il.Add(loadA);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(loadB);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(loadDefault);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildStoreRegistersMethod(ModuleDef module, FieldDef regA, FieldDef regB, FieldDef regC)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            var storeB = Instruction.Create(DnOpCodes.Ldarg_1);
            var storeEnd = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            var storeA = Instruction.Create(DnOpCodes.Ldarg_1);
            il.Add(Instruction.Create(DnOpCodes.Beq, storeA));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Beq, storeB));
            il.Add(Instruction.Create(DnOpCodes.Br, storeEnd));

            il.Add(storeA);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, regA));
            il.Add(Instruction.Create(DnOpCodes.Br, storeEnd));

            il.Add(storeB);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, regB));

            il.Add(storeEnd);

            return method;
        }

        private MethodDef BuildCheckHaltMethod(ModuleDef module, FieldDef haltFlag, FieldDef ip, FieldDef flagReg)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retTrue = Instruction.Create(DnOpCodes.Ldc_I4_1);
            var retFalse = Instruction.Create(DnOpCodes.Ldc_I4_0);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, haltFlag));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, retTrue));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, ip));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Blt, retTrue));
            il.Add(Instruction.Create(DnOpCodes.Br, retFalse));

            il.Add(retTrue);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(retFalse);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildOpcodeAddMethod(ModuleDef module, FieldDef result, FieldDef operand, FieldDef carry)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int64));

            var il = method.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Ldarg_0);
            var tryEnd = Instruction.Create(DnOpCodes.Nop);
            var catchStart = Instruction.Create(DnOpCodes.Pop);
            var catchEnd = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, result));
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));

            il.Add(catchStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, carry));
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));

            il.Add(tryEnd);

            il.Add(catchEnd);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = catchStart,
                HandlerStart = catchStart,
                HandlerEnd = tryEnd,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return method;
        }

        private MethodDef BuildOpcodeSubMethod(ModuleDef module, FieldDef result, FieldDef operand, FieldDef carry)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var noCarry = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ble, noCarry));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, carry));

            il.Add(noCarry);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, result));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildOpcodeXorMethod(ModuleDef module, FieldDef result, FieldDef operand, FieldDef flags)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, result));

            var notZero = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Bne_Un, notZero));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, flags));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 128)));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, flags));

            il.Add(notZero);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildOpcodeLoadMethod(ModuleDef module, FieldDef result, FieldDef acc, FieldDef opcType)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 255)));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, acc));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, result));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildOpcodeStoreMethod(ModuleDef module, FieldDef result, FieldDef acc, FieldDef operand)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, result));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, acc));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, operand));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildOpcodeBranchMethod(ModuleDef module, FieldDef result, FieldDef flags, FieldDef operand)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ldloc_1);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var takeBranch = Instruction.Create(DnOpCodes.Ldarg_0);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, flags));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 64)));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Bne_Un, takeBranch));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(takeBranch);
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, result));

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildOpcodeCompareMethod(ModuleDef module, FieldDef result, FieldDef operand, FieldDef flags, FieldDef carry)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            var equal = Instruction.Create(DnOpCodes.Ldc_I4_0);
            var greater = Instruction.Create(DnOpCodes.Ldc_I4_1);
            var less = Instruction.Create(DnOpCodes.Ldc_I4_M1);
            var done = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Beq, equal));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Bgt, greater));
            il.Add(Instruction.Create(DnOpCodes.Br, less));

            il.Add(equal);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, flags));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 64)));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, flags));
            il.Add(Instruction.Create(DnOpCodes.Br, done));

            il.Add(greater);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, done));

            il.Add(less);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, carry));

            il.Add(done);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, result));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildOpcodeNotMethod(ModuleDef module, FieldDef result, FieldDef operand, FieldDef flags)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, result));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, operand));

            var notZero = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Bne_Un, notZero));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, flags));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 64)));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, flags));

            il.Add(notZero);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildStackPushMethod(ModuleDef module, FieldDef stackData, FieldDef stackTop,
            FieldDef stackCapacity, FieldDef stackOverflow)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var overflowLabel = Instruction.Create(DnOpCodes.Ldc_I4_1);
            var retLabel = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackCapacity));
            il.Add(Instruction.Create(DnOpCodes.Bge, overflowLabel));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackData));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(overflowLabel);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackOverflow));

            il.Add(retLabel);

            return method;
        }

        private MethodDef BuildStackPopMethod(ModuleDef module, FieldDef stackData, FieldDef stackTop, FieldDef stackOverflow)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var underflow = Instruction.Create(DnOpCodes.Ldc_I4_1);
            var retLabel = Instruction.Create(DnOpCodes.Ldloc_1);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ble, underflow));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackData));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Br, retLabel));

            il.Add(underflow);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackOverflow));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildStackPeekMethod(ModuleDef module, FieldDef stackData, FieldDef stackTop)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var empty = Instruction.Create(DnOpCodes.Ldc_I4_0);
            var retLabel = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ble, empty));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackData));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_I4));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(empty);
            il.Add(retLabel);

            return method;
        }

        private MethodDef BuildInitStackMethod(ModuleDef module, FieldDef stackData, FieldDef stackTop,
            FieldDef stackCapacity, FieldDef stackOverflow, FieldDef stackFrameBase, FieldDef stackHash)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;
            int cap = rng.Next(384, 1280);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, cap));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackData));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, cap));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackCapacity));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackOverflow));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackFrameBase));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(int.MinValue, int.MaxValue)));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, stackHash));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildStackDepthMethod(ModuleDef module, FieldDef stackTop, FieldDef stackFrameBase)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackTop));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, stackFrameBase));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildMemoryReadMethod(ModuleDef module, FieldDef memData, FieldDef memSize,
            FieldDef memBase, FieldDef memProtect)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Ldarg_0);
            var tryEnd = Instruction.Create(DnOpCodes.Nop);
            var catchStart = Instruction.Create(DnOpCodes.Pop);
            var catchEnd = Instruction.Create(DnOpCodes.Ldloc_1);

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memBase));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var outOfBounds = Instruction.Create(DnOpCodes.Ldc_I4_M1);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Blt, outOfBounds));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memSize));
            il.Add(Instruction.Create(DnOpCodes.Bge, outOfBounds));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memData));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));

            il.Add(outOfBounds);
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));

            il.Add(catchStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));

            il.Add(tryEnd);

            il.Add(catchEnd);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = catchStart,
                HandlerStart = catchStart,
                HandlerEnd = tryEnd,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return method;
        }

        private MethodDef BuildMemoryWriteMethod(ModuleDef module, FieldDef memData, FieldDef memSize,
            FieldDef memBase, FieldDef memProtect, FieldDef memChecksum)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memProtect));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, retLabel));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memBase));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var outOfBounds = Instruction.Create(DnOpCodes.Ret);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Blt, outOfBounds));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memSize));
            il.Add(Instruction.Create(DnOpCodes.Bge, outOfBounds));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memData));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Conv_U1));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I1));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memChecksum));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memChecksum));

            il.Add(retLabel);
            il.Add(outOfBounds);

            return method;
        }

        private MethodDef BuildMemoryAllocMethod(ModuleDef module, FieldDef memData, FieldDef memSize,
            FieldDef memAllocCount, FieldDef memPageTable)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ble, retLabel));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memData));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memSize));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memAllocCount));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memAllocCount));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(64, 256)));
            il.Add(Instruction.Create(DnOpCodes.Div));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memPageTable));

            il.Add(retLabel);

            return method;
        }

        private MethodDef BuildMemoryChecksumMethod(ModuleDef module, FieldDef memData, FieldDef memSize, FieldDef memChecksum)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(int.MinValue, int.MaxValue)));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var loopStart = Instruction.Create(DnOpCodes.Ldloc_1);
            var loopEnd = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memSize));
            il.Add(Instruction.Create(DnOpCodes.Bge, loopEnd));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memData));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            il.Add(loopEnd);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memChecksum));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, memChecksum));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildInitMemoryMethod(ModuleDef module, FieldDef memData, FieldDef memSize,
            FieldDef memBase, FieldDef memProtect, FieldDef memChecksum, FieldDef memAllocCount, FieldDef memPageTable)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            var il = method.Body.Instructions;
            int memSizeVal = rng.Next(1024, 12288);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, memSizeVal));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memData));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, memSizeVal));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memSize));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(0, 65536)));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memBase));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memProtect));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memChecksum));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memAllocCount));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, memSizeVal / rng.Next(64, 256)));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, memPageTable));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }
    }
}

