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
    internal class AntiHookProtection
    {
        private readonly Obfuscation engine;
        private readonly Random rng;

        private struct ApiCheck
        {
            public string Module;
            public string Function;
            public byte[][] AcceptedX86;
            public byte[][] AcceptedX64;
        }

        private static readonly ApiCheck[] ApiTable = new ApiCheck[]
        {

            new ApiCheck {
                Module = "kernel32.dll",
                Function = "IsDebuggerPresent",

                AcceptedX86 = new byte[][] {
                    new byte[] { 0x64, 0xA1 }, new byte[] { 0xFF, 0x25 }, new byte[] { 0x55, 0x8B },
                    new byte[] { 0x8B, 0xFF }, new byte[] { 0x6A, 0x00 }, new byte[] { 0x33, 0xC0 },
                    new byte[] { 0xB8, 0x00 }, new byte[] { 0xE9, 0x00 }, new byte[] { 0xEB, 0x00 },
                },

                AcceptedX64 = new byte[][] {
                    new byte[] { 0x65, 0x48 }, new byte[] { 0x48, 0xFF }, new byte[] { 0x48, 0x83 },
                    new byte[] { 0x48, 0x89 }, new byte[] { 0x40, 0x53 }, new byte[] { 0x48, 0x8B },
                    new byte[] { 0x4C, 0x8B }, new byte[] { 0x33, 0xC0 }, new byte[] { 0xCC, 0xCC },
                },
            },
            new ApiCheck {
                Module = "kernel32.dll",
                Function = "CheckRemoteDebuggerPresent",
                AcceptedX86 = new byte[][] {
                    new byte[] { 0xFF, 0x25 }, new byte[] { 0x8B, 0xFF }, new byte[] { 0x55, 0x8B },
                    new byte[] { 0x6A, 0x00 }, new byte[] { 0x33, 0xC0 }, new byte[] { 0x57, 0x56 },
                    new byte[] { 0xB8, 0x00 }, new byte[] { 0x83, 0xEC },
                },
                AcceptedX64 = new byte[][] {
                    new byte[] { 0x48, 0x83 }, new byte[] { 0x48, 0xFF }, new byte[] { 0x40, 0x53 },
                    new byte[] { 0x48, 0x89 }, new byte[] { 0x48, 0x8B }, new byte[] { 0x4C, 0x8B },
                    new byte[] { 0x33, 0xC0 }, new byte[] { 0x57, 0x56 }, new byte[] { 0xCC, 0xCC },
                },
            },
            new ApiCheck {
                Module = "kernel32.dll",
                Function = "OutputDebugStringA",
                AcceptedX86 = new byte[][] {
                    new byte[] { 0xFF, 0x25 }, new byte[] { 0x8B, 0xFF }, new byte[] { 0x55, 0x8B },
                    new byte[] { 0x6A, 0x00 }, new byte[] { 0x6A, 0x18 }, new byte[] { 0x83, 0xEC },
                    new byte[] { 0xB8, 0x00 },
                },
                AcceptedX64 = new byte[][] {
                    new byte[] { 0x48, 0x83 }, new byte[] { 0x48, 0x89 }, new byte[] { 0x48, 0xFF },
                    new byte[] { 0x40, 0x53 }, new byte[] { 0x48, 0x8B }, new byte[] { 0x4C, 0x8B },
                    new byte[] { 0x33, 0xC0 }, new byte[] { 0xCC, 0xCC },
                },
            },
            new ApiCheck {
                Module = "ntdll.dll",
                Function = "NtQueryInformationProcess",

                AcceptedX86 = new byte[][] {
                    new byte[] { 0xB8, 0x19 }, new byte[] { 0xB8, 0x16 }, new byte[] { 0xB8, 0x9A },
                    new byte[] { 0xB8, 0xCF }, new byte[] { 0xB8, 0xCE }, new byte[] { 0xB8, 0xCB },
                    new byte[] { 0xB8, 0xCC }, new byte[] { 0xB8, 0xCD }, new byte[] { 0xB8, 0xD2 },
                    new byte[] { 0xB8, 0xD3 }, new byte[] { 0xB8, 0xD4 }, new byte[] { 0xB8, 0xD5 },
                    new byte[] { 0xB8, 0xD6 }, new byte[] { 0xB8, 0xD7 }, new byte[] { 0xB8, 0xD8 },
                },
                AcceptedX64 = new byte[][] {
                    new byte[] { 0x4C, 0x8B }, new byte[] { 0x48, 0x8B }, new byte[] { 0xB8, 0x19 },
                    new byte[] { 0xB8, 0x16 }, new byte[] { 0xB8, 0x9A }, new byte[] { 0xB8, 0xCF },
                    new byte[] { 0xB8, 0xCE }, new byte[] { 0xB8, 0xCD }, new byte[] { 0xB8, 0xD2 },
                    new byte[] { 0xB8, 0xD3 }, new byte[] { 0xB8, 0xD4 }, new byte[] { 0xB8, 0xD5 },
                    new byte[] { 0xB8, 0xD6 }, new byte[] { 0xB8, 0xD7 }, new byte[] { 0xB8, 0xD8 },
                },
            },
        };

        internal AntiHookProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiHook(ModuleDef module, TypeDef modType)
        {

            int wantCount = rng.Next(2, ApiTable.Length + 1);
            var picked = ApiTable.OrderBy(_ => rng.Next()).Take(wantCount).ToArray();

            var hookType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            hookType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(hookType);
            engine.injectedTypes.Add(hookType);

            var loadLib = ImportPInvoke(module, hookType, "LoadLibraryA",   "kernel32.dll", typeof(IntPtr), new[] { typeof(string) });
            var getProc = ImportPInvoke(module, hookType, "GetProcAddress", "kernel32.dll", typeof(IntPtr), new[] { typeof(IntPtr), typeof(string) });

            engine.injectedMethods.Add(loadLib);
            engine.injectedMethods.Add(getProc);

            var is64Process   = module.Import(typeof(Environment).GetProperty("Is64BitProcess").GetGetMethod());
            NativeShroud shroud = engine.EnsureShroud(module);

            MethodDef decoder = BuildStringDecoder(module, hookType);
            hookType.Methods.Add(decoder);
            engine.injectedMethods.Add(decoder);

            var checkMethod = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            checkMethod.Body = new CilBody();
            checkMethod.Body.InitLocals = true;

            var ipSig = module.Import(typeof(IntPtr)).ToTypeSig();
            checkMethod.Body.Variables.Add(new Local(ipSig));
            checkMethod.Body.Variables.Add(new Local(ipSig));
            checkMethod.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            checkMethod.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

            var il = checkMethod.Body.Instructions;

            var afterTry = Instruction.Create(DnOpCodes.Ret);
            var tryStart = Instruction.Create(DnOpCodes.Call, is64Process);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            foreach (var api in picked)
            {
                EmitApiCheck(module, hookType, il, api, loadLib, getProc, shroud, decoder);
            }

            il.Add(Instruction.Create(DnOpCodes.Leave, afterTry));

            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Leave, afterTry));
            il.Add(afterTry);

            checkMethod.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = afterTry,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef,
            });

            hookType.Methods.Add(checkMethod);
            engine.injectedMethods.Add(checkMethod);
            engine.InjectCallAtTop(module, modType, checkMethod);

            var bgMonitor = BuildBackgroundHookMonitor(module, checkMethod);
            hookType.Methods.Add(bgMonitor);
            engine.injectedMethods.Add(bgMonitor);

            var startBg = BuildBackgroundStarter(module, bgMonitor);
            hookType.Methods.Add(startBg);
            engine.injectedMethods.Add(startBg);
            engine.InjectCallInCctor(module, modType, startBg);
        }

        private MethodDef BuildBackgroundHookMonitor(ModuleDef module, MethodDef scanner)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();

            var threadSleep = module.Import(typeof(System.Threading.Thread).GetMethod("Sleep", new[] { typeof(int) }));
            var il = method.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Call, scanner);
            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            var beforeSleep = Instruction.Create(DnOpCodes.Ldc_I4, 1000 + rng.Next(0, 2000));

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Leave, beforeSleep));
            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Leave, beforeSleep));
            il.Add(beforeSleep);
            il.Add(Instruction.Create(DnOpCodes.Call, threadSleep));
            il.Add(Instruction.Create(DnOpCodes.Br, tryStart));

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = beforeSleep,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return method;
        }

        private MethodDef BuildBackgroundStarter(ModuleDef module, MethodDef bgEntry)
        {
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

            var tryStart = Instruction.Create(DnOpCodes.Ldnull);
            sbIl.Add(tryStart);
            sbIl.Add(Instruction.Create(DnOpCodes.Ldftn, bgEntry));
            sbIl.Add(Instruction.Create(DnOpCodes.Newobj, threadStartCtor));
            sbIl.Add(Instruction.Create(DnOpCodes.Newobj, threadCtor));
            sbIl.Add(Instruction.Create(DnOpCodes.Stloc_0));
            sbIl.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            sbIl.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            sbIl.Add(Instruction.Create(DnOpCodes.Callvirt, threadSetBg));
            sbIl.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            sbIl.Add(Instruction.Create(DnOpCodes.Callvirt, threadStart));

            var retInst = Instruction.Create(DnOpCodes.Ret);
            sbIl.Add(Instruction.Create(DnOpCodes.Leave, retInst));
            var catchInst = Instruction.Create(DnOpCodes.Pop);
            sbIl.Add(catchInst);
            sbIl.Add(Instruction.Create(DnOpCodes.Leave, retInst));
            sbIl.Add(retInst);

            startBg.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = catchInst,
                HandlerStart = catchInst,
                HandlerEnd = retInst,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return startBg;
        }

        private void EmitApiCheck(ModuleDef module, TypeDef hookType, IList<Instruction> il, ApiCheck api,
            MethodDef loadLib, MethodDef getProc, NativeShroud shroud, MethodDef decoder)
        {
            EmitEncryptedStringLoad(module, hookType, il, api.Module, decoder);
            il.Add(Instruction.Create(DnOpCodes.Call, loadLib));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            var skipApi = Instruction.Create(DnOpCodes.Nop);
            var ipZero  = module.Import(typeof(IntPtr).GetField("Zero"));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, ipZero));

            var ipEq = module.Import(typeof(IntPtr).GetMethod("op_Equality", new[] { typeof(IntPtr), typeof(IntPtr) }));
            il.Add(Instruction.Create(DnOpCodes.Call, ipEq));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, skipApi));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            EmitEncryptedStringLoad(module, hookType, il, api.Function, decoder);
            il.Add(Instruction.Create(DnOpCodes.Call, getProc));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, ipZero));
            il.Add(Instruction.Create(DnOpCodes.Call, ipEq));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, skipApi));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldind_U1));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Conv_I));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldind_U1));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I1));

            var x64Branch = Instruction.Create(DnOpCodes.Nop);
            var afterChecks = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, x64Branch));

            EmitPatternMatch(il, api.AcceptedX86, shroud, afterChecks);
            il.Add(Instruction.Create(DnOpCodes.Br, afterChecks));

            il.Add(x64Branch);
            EmitPatternMatch(il, api.AcceptedX64, shroud, afterChecks);

            il.Add(afterChecks);
            il.Add(skipApi);
        }

        private void EmitPatternMatch(IList<Instruction> il, byte[][] patterns, NativeShroud shroud, Instruction afterChecks)
        {
            var passed = Instruction.Create(DnOpCodes.Br, afterChecks);

            foreach (var pat in patterns)
            {
                var nextPat = Instruction.Create(DnOpCodes.Nop);
                il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)pat[0]));
                il.Add(Instruction.Create(DnOpCodes.Bne_Un, nextPat));
                il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)pat[1]));
                il.Add(Instruction.Create(DnOpCodes.Bne_Un, nextPat));
                il.Add(Instruction.Create(DnOpCodes.Br, passed));
                il.Add(nextPat);
            }

            engine.EmitAntiCrackHook(il);
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
            il.Add(Instruction.Create(DnOpCodes.Pop));
            il.Add(passed);
        }

        private MethodDef BuildStringDecoder(ModuleDef module, TypeDef owner)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.String,
                    new SZArraySig(module.CorLibTypes.Byte),
                    module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Char)));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            Importer importer = new Importer(module);
            IMethod strCtor = importer.Import(typeof(string).GetConstructor(new Type[] { typeof(char[]) }));

            IList<Instruction> il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Char.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            Instruction loopCond = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, loopCond));

            Instruction loopBody = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Conv_U2));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I2));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(loopCond);
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Newobj, strCtor));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private void EmitEncryptedStringLoad(ModuleDef module, TypeDef owner,
            IList<Instruction> il, string plain, MethodDef decoder)
        {
            byte[] data = System.Text.Encoding.ASCII.GetBytes(plain);
            int seed = rng.Next(1, 256);
            byte[] cipher = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                cipher[i] = (byte)(data[i] ^ ((seed + i) & 0xFF));

            FieldDef rvaField = EmitRvaCharField(module, owner, cipher);

            Importer importer = new Importer(module);
            ITypeDefOrRef sysByte = importer.Import(typeof(byte));
            IMethod rhInitArr = importer.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers)
                .GetMethod("InitializeArray",
                    new Type[] { typeof(Array), typeof(RuntimeFieldHandle) }));

            il.Add(engine.LoadInt(cipher.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, sysByte));
            il.Add(Instruction.Create(DnOpCodes.Dup));
            il.Add(Instruction.Create(DnOpCodes.Ldtoken, rvaField));
            il.Add(Instruction.Create(DnOpCodes.Call, rhInitArr));
            il.Add(engine.LoadInt(seed));
            il.Add(Instruction.Create(DnOpCodes.Call, decoder));
        }

        private FieldDef EmitRvaCharField(ModuleDef module, TypeDef owner, byte[] bytes)
        {
            Importer importer = new Importer(module);
            ITypeDefOrRef sysValueType = importer.Import(typeof(ValueType));

            string holderName = engine.MakeName();
            TypeDef holder = new TypeDefUser("", holderName, sysValueType);
            holder.Attributes = DnTypeAttributes.NestedPrivate
                              | DnTypeAttributes.SequentialLayout
                              | DnTypeAttributes.Sealed;
            holder.ClassLayout = new ClassLayoutUser(1, (uint)bytes.Length);
            owner.NestedTypes.Add(holder);
            engine.injectedTypes.Add(holder);

            FieldDef rvaField = new FieldDefUser(engine.MakeName(),
                new FieldSig(holder.ToTypeSig()),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static
                | DnFieldAttributes.HasFieldRVA);
            rvaField.HasFieldRVA = true;
            rvaField.InitialValue = (byte[])bytes.Clone();
            owner.Fields.Add(rvaField);

            return rvaField;
        }

        private MethodDef ImportPInvoke(ModuleDef module, TypeDef owner,
            string entryPoint, string dllName, Type retType, Type[] paramTypes)
        {
            var sigParams = new TypeSig[paramTypes.Length];
            for (int i = 0; i < paramTypes.Length; i++)
                sigParams[i] = module.Import(paramTypes[i]).ToTypeSig();
            var retSig = module.Import(retType).ToTypeSig();

            var m = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(retSig, sigParams),
                DnMethodImplAttributes.PreserveSig,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static |
                DnMethodAttributes.HideBySig | DnMethodAttributes.PinvokeImpl);

            var mod = new ModuleRefUser(module, dllName);
            m.ImplMap = new ImplMapUser(mod, entryPoint,
                PInvokeAttributes.CallConvWinapi | PInvokeAttributes.CharSetAnsi);

            owner.Methods.Add(m);
            return m;
        }
    }
}

