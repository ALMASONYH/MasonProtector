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
    internal class AntiDumpProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal AntiDumpProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiDump(ModuleDef module, TypeDef modType)
        {
            var dumpType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            dumpType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

            for (int i = 0; i < rng.Next(10, 24); i++)
            {
                dumpType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.IntPtr),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }

            var eraseMethod = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            eraseMethod.Body = new CilBody();
            eraseMethod.Body.InitLocals = true;
            eraseMethod.Body.Variables.Add(new Local(module.CorLibTypes.IntPtr));
            eraseMethod.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            eraseMethod.Body.Variables.Add(new Local(module.CorLibTypes.UInt32));

            var il = eraseMethod.Body.Instructions;

            var getExecAsm = module.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly", Type.EmptyTypes));
            var getManifestModule = module.Import(typeof(System.Reflection.Assembly).GetProperty("ManifestModule").GetGetMethod());
            var getModuleHandle = module.Import(typeof(System.Runtime.InteropServices.Marshal).GetMethod("GetHINSTANCE",
                new[] { typeof(System.Reflection.Module) }));

            int constA = rng.Next(int.MinValue, int.MaxValue);
            int constB = rng.Next(int.MinValue, int.MaxValue);

            var eraseFinally = Instruction.Create(DnOpCodes.Ret);
            var exitLeave    = Instruction.Create(DnOpCodes.Leave, eraseFinally);

            var tryStart = Instruction.Create(DnOpCodes.Call, getExecAsm);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getManifestModule));
            il.Add(Instruction.Create(DnOpCodes.Call, getModuleHandle));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, constA));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, constB));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Conv_U));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(exitLeave);

            var eraseCatch = Instruction.Create(DnOpCodes.Pop);
            il.Add(eraseCatch);
            il.Add(Instruction.Create(DnOpCodes.Leave, eraseFinally));

            il.Add(eraseFinally);

            eraseMethod.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart     = tryStart,
                TryEnd       = eraseCatch,
                HandlerStart = eraseCatch,
                HandlerEnd   = eraseFinally,
                CatchType    = module.CorLibTypes.Object.TypeDefOrRef
            });

            dumpType.Methods.Add(eraseMethod);
            engine.injectedMethods.Add(eraseMethod);
            module.Types.Add(dumpType);
            engine.injectedTypes.Add(dumpType);
            engine.InjectCallInCctor(module, modType, eraseMethod);

            for (int i = 0; i < rng.Next(8, 18); i++)
            {
                var trapType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                trapType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;

                trapType.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.IntPtr),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));

                module.Types.Add(trapType);
                engine.injectedTypes.Add(trapType);
            }
        }
    }
}

