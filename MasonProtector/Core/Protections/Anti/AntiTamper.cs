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
    internal class AntiTamperProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal AntiTamperProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiTamper(ModuleDef module, TypeDef modType)
        {
            var tamperType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            tamperType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

            var hashField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            tamperType.Fields.Add(hashField);

            var sizeField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Private | DnFieldAttributes.Static);
            tamperType.Fields.Add(sizeField);

            for (int d = 0; d < rng.Next(10, 20); d++)
            {
                tamperType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }

            var tamperMethod = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            tamperMethod.Body = new CilBody();
            tamperMethod.Body.InitLocals = true;
            tamperMethod.Body.Variables.Add(new Local(module.CorLibTypes.String));
            tamperMethod.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            tamperMethod.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            tamperMethod.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            tamperMethod.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

            var il = tamperMethod.Body.Instructions;

            var getExecAsm = module.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly", Type.EmptyTypes));
            var getLocation = module.Import(typeof(System.Reflection.Assembly).GetProperty("Location").GetGetMethod());
            var fileReadAll = module.Import(typeof(System.IO.File).GetMethod("ReadAllBytes", new[] { typeof(string) }));

            var strIsNullOrEmpty = module.Import(typeof(string).GetMethod("IsNullOrEmpty", new[] { typeof(string) }));

            var sha256Create = module.Import(typeof(System.Security.Cryptography.SHA256).GetMethod("Create", Type.EmptyTypes));
            var computeHash = module.Import(typeof(System.Security.Cryptography.HashAlgorithm).GetMethod("ComputeHash", new[] { typeof(byte[]) }));

            var earlyRet = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Call, getExecAsm));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getLocation));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Call, strIsNullOrEmpty));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, earlyRet));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Call, fileReadAll));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var sizeOk = Instruction.Create(DnOpCodes.Nop);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 2048));
            il.Add(Instruction.Create(DnOpCodes.Bge, sizeOk));
            il.Add(Instruction.Create(DnOpCodes.Br, earlyRet));

            il.Add(sizeOk);
            il.Add(Instruction.Create(DnOpCodes.Call, sha256Create));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, computeHash));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, hashField));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, sizeField));

            il.Add(earlyRet);

            tamperType.Methods.Add(tamperMethod);
            engine.injectedMethods.Add(tamperMethod);
            module.Types.Add(tamperType);
            engine.injectedTypes.Add(tamperType);
            engine.InjectCallInCctor(module, modType, tamperMethod);

            var bgVerify = BuildTamperBackgroundVerifier(module, tamperType, hashField, sizeField);
            tamperType.Methods.Add(bgVerify);
            engine.injectedMethods.Add(bgVerify);

            var startBg = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            startBg.Body = new CilBody();
            startBg.Body.InitLocals = true;
            startBg.Body.Variables.Add(new Local(module.Import(typeof(System.Threading.Thread)).ToTypeSig()));
            var sbIl = startBg.Body.Instructions;

            var threadStartCtor = module.Import(typeof(System.Threading.ThreadStart).GetConstructor(
                new[] { typeof(object), typeof(IntPtr) }));
            var threadCtor = module.Import(typeof(System.Threading.Thread).GetConstructor(
                new[] { typeof(System.Threading.ThreadStart) }));
            var threadSetBg = module.Import(typeof(System.Threading.Thread).GetProperty("IsBackground").GetSetMethod());
            var threadStart = module.Import(typeof(System.Threading.Thread).GetMethod("Start", Type.EmptyTypes));

            var tamperTryStart = Instruction.Create(DnOpCodes.Ldnull);
            sbIl.Add(tamperTryStart);
            sbIl.Add(Instruction.Create(DnOpCodes.Ldftn, bgVerify));
            sbIl.Add(Instruction.Create(DnOpCodes.Newobj, threadStartCtor));
            sbIl.Add(Instruction.Create(DnOpCodes.Newobj, threadCtor));
            sbIl.Add(Instruction.Create(DnOpCodes.Stloc_0));
            sbIl.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            sbIl.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            sbIl.Add(Instruction.Create(DnOpCodes.Callvirt, threadSetBg));
            sbIl.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            sbIl.Add(Instruction.Create(DnOpCodes.Callvirt, threadStart));
            var tamperRetInst = Instruction.Create(DnOpCodes.Ret);
            sbIl.Add(Instruction.Create(DnOpCodes.Leave, tamperRetInst));
            var tamperCatchInst = Instruction.Create(DnOpCodes.Pop);
            sbIl.Add(tamperCatchInst);
            sbIl.Add(Instruction.Create(DnOpCodes.Leave, tamperRetInst));
            sbIl.Add(tamperRetInst);

            startBg.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tamperTryStart,
                TryEnd = tamperCatchInst,
                HandlerStart = tamperCatchInst,
                HandlerEnd = tamperRetInst,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            tamperType.Methods.Add(startBg);
            engine.injectedMethods.Add(startBg);
            engine.InjectCallInCctor(module, modType, startBg);

            engine.InjectCallInRandomMethods(module, tamperMethod, 4, 9);
            engine.InjectCallInRandomMethods(module, startBg,      6, 14);
        }

        private MethodDef BuildTamperBackgroundVerifier(ModuleDef module, TypeDef owner,
            FieldDef hashField, FieldDef sizeField)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            method.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.String));

            var il = method.Body.Instructions;

            var threadSleep   = module.Import(typeof(System.Threading.Thread).GetMethod("Sleep", new[] { typeof(int) }));
            var getExecAsm    = module.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly", Type.EmptyTypes));
            var getLocation   = module.Import(typeof(System.Reflection.Assembly).GetProperty("Location").GetGetMethod());
            var fileReadAll   = module.Import(typeof(System.IO.File).GetMethod("ReadAllBytes", new[] { typeof(string) }));
            var strIsNullOrEmpty = module.Import(typeof(string).GetMethod("IsNullOrEmpty", new[] { typeof(string) }));
            var sha256Create  = module.Import(typeof(System.Security.Cryptography.SHA256).GetMethod("Create", Type.EmptyTypes));
            var computeHash   = module.Import(typeof(System.Security.Cryptography.HashAlgorithm).GetMethod("ComputeHash", new[] { typeof(byte[]) }));
            NativeShroud shroud = engine.EnsureShroud(module);

            var loopStart  = Instruction.Create(DnOpCodes.Ldc_I4, 1500 + rng.Next(0, 3500));
            var afterCatch = Instruction.Create(DnOpCodes.Br, loopStart);

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Call, threadSleep));

            var tryStart = Instruction.Create(DnOpCodes.Call, getExecAsm);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getLocation));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[3]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[3]));
            il.Add(Instruction.Create(DnOpCodes.Call, strIsNullOrEmpty));
            var continueAfterNullCheck = Instruction.Create(DnOpCodes.Ldsfld, sizeField);
            il.Add(Instruction.Create(DnOpCodes.Brfalse, continueAfterNullCheck));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

            il.Add(continueAfterNullCheck);
            var continueAfterSizeCheck = Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[3]);
            il.Add(Instruction.Create(DnOpCodes.Brtrue, continueAfterSizeCheck));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

            il.Add(continueAfterSizeCheck);
            il.Add(Instruction.Create(DnOpCodes.Call, fileReadAll));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, sizeField));
            var sizeOk = Instruction.Create(DnOpCodes.Call, sha256Create);
            il.Add(Instruction.Create(DnOpCodes.Beq, sizeOk));
            engine.EmitAntiCrackHook(il);
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
            il.Add(Instruction.Create(DnOpCodes.Pop));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

            il.Add(sizeOk);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, computeHash));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            var hashLoopStart = Instruction.Create(DnOpCodes.Ldloc_2);
            var hashLoopBody  = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, hashLoopStart));

            il.Add(hashLoopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, hashField));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            var hashMatch = Instruction.Create(DnOpCodes.Ldloc_2);
            il.Add(Instruction.Create(DnOpCodes.Beq, hashMatch));
            engine.EmitAntiCrackHook(il);
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
            il.Add(Instruction.Create(DnOpCodes.Pop));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

            il.Add(hashMatch);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(hashLoopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Blt, hashLoopBody));

            il.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

            var catchStart = Instruction.Create(DnOpCodes.Pop);
            il.Add(catchStart);
            il.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

            il.Add(afterCatch);

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart     = tryStart,
                TryEnd       = catchStart,
                HandlerStart = catchStart,
                HandlerEnd   = afterCatch,
                CatchType    = module.CorLibTypes.Object.TypeDefOrRef
            });

            return method;
        }
    }
}

