using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;
using DnPInvokeAttributes = dnlib.DotNet.PInvokeAttributes;
using DnCallingConvention = dnlib.DotNet.CallingConvention;

namespace MasonProtector.Core
{

    internal class NativeShroud
    {
        private readonly Obfuscation engine;
        private readonly ModuleDef module;
        private readonly TypeDef container;

        internal MethodDef IsDebuggerPresent;
        internal MethodDef CheckRemoteDebuggerPresent;
        internal MethodDef NtQueryInformationProcess;
        internal MethodDef NtSetInformationThread;
        internal MethodDef GetCurrentProcess;
        internal MethodDef GetCurrentThread;
        internal MethodDef GetCurrentProcessId;
        internal MethodDef TerminateProcess;
        internal MethodDef ExitProcess;
        internal MethodDef CreateToolhelp32Snapshot;
        internal MethodDef Process32FirstW;
        internal MethodDef Process32NextW;
        internal MethodDef Module32FirstW;
        internal MethodDef Module32NextW;
        internal MethodDef CloseHandle;
        internal MethodDef GetTickCount;
        internal MethodDef GetLastError;
        internal MethodDef SetLastError;

        private ModuleRef refKernel32;
        private MethodDef _pLoadLibraryA;
        private MethodDef _pGetProcAddress;
        private MethodDef _decryptString;
        private FieldDef  _hKernel32;
        private FieldDef  _hNtdll;
        private byte      _xorKey;

        private TypeSig _tsIntPtr;
        private TypeSig _tsString;
        private TypeSig _tsBoolean;
        private TypeSig _tsInt32;
        private TypeSig _tsUInt32;

        internal NativeShroud(Obfuscation eng, ModuleDef mod, TypeDef containerType)
        {
            engine = eng;
            module = mod;
            container = containerType;
        }

        internal void Build()
        {
            refKernel32 = GetOrCreateModuleRef("kernel32.dll");
            _xorKey = (byte)(1 + (engine.rng.Next() % 254));

            _tsIntPtr  = module.CorLibTypes.IntPtr;
            _tsString  = module.CorLibTypes.String;
            _tsBoolean = module.CorLibTypes.Boolean;
            _tsInt32   = module.CorLibTypes.Int32;
            _tsUInt32  = module.CorLibTypes.UInt32;

            _pLoadLibraryA = MakeStaticPInvoke("LoadLibraryA", refKernel32,
                MethodSig.CreateStatic(_tsIntPtr, _tsString),
                DnPInvokeAttributes.CallConvWinapi | DnPInvokeAttributes.CharSetAnsi);

            _pGetProcAddress = MakeStaticPInvoke("GetProcAddress", refKernel32,
                MethodSig.CreateStatic(_tsIntPtr, _tsIntPtr, _tsString),
                DnPInvokeAttributes.CallConvWinapi | DnPInvokeAttributes.CharSetAnsi);

            _hKernel32 = AddIntPtrField();
            _hNtdll    = AddIntPtrField();

            _decryptString = BuildDecryptHelper();

            IsDebuggerPresent = BuildResolver("kernel32.dll", "IsDebuggerPresent",
                _tsBoolean, new TypeSig[0]);

            CheckRemoteDebuggerPresent = BuildResolver("kernel32.dll", "CheckRemoteDebuggerPresent",
                _tsBoolean, new TypeSig[] {
                    _tsIntPtr,
                    new ByRefSig(_tsInt32),
                });

            NtQueryInformationProcess = BuildResolver("ntdll.dll", "NtQueryInformationProcess",
                _tsInt32, new TypeSig[] {
                    _tsIntPtr, _tsInt32, _tsIntPtr, _tsUInt32,
                    new ByRefSig(_tsUInt32),
                });

            NtSetInformationThread = BuildResolver("ntdll.dll", "NtSetInformationThread",
                _tsInt32, new TypeSig[] {
                    _tsIntPtr, _tsInt32, _tsIntPtr, _tsUInt32,
                });

            GetCurrentProcess = BuildResolver("kernel32.dll", "GetCurrentProcess",
                _tsIntPtr, new TypeSig[0]);

            GetCurrentThread = BuildResolver("kernel32.dll", "GetCurrentThread",
                _tsIntPtr, new TypeSig[0]);

            GetCurrentProcessId = BuildResolver("kernel32.dll", "GetCurrentProcessId",
                _tsUInt32, new TypeSig[0]);

            TerminateProcess = BuildResolver("kernel32.dll", "TerminateProcess",
                _tsBoolean, new TypeSig[] { _tsIntPtr, _tsUInt32 });

            ExitProcess = BuildResolver("kernel32.dll", "ExitProcess",
                module.CorLibTypes.Void, new TypeSig[] { _tsUInt32 });

            CreateToolhelp32Snapshot = BuildResolver("kernel32.dll", "CreateToolhelp32Snapshot",
                _tsIntPtr, new TypeSig[] { _tsUInt32, _tsUInt32 });

            Process32FirstW = BuildResolver("kernel32.dll", "Process32FirstW",
                _tsBoolean, new TypeSig[] { _tsIntPtr, _tsIntPtr });

            Process32NextW = BuildResolver("kernel32.dll", "Process32NextW",
                _tsBoolean, new TypeSig[] { _tsIntPtr, _tsIntPtr });

            Module32FirstW = BuildResolver("kernel32.dll", "Module32FirstW",
                _tsBoolean, new TypeSig[] { _tsIntPtr, _tsIntPtr });

            Module32NextW = BuildResolver("kernel32.dll", "Module32NextW",
                _tsBoolean, new TypeSig[] { _tsIntPtr, _tsIntPtr });

            CloseHandle = BuildResolver("kernel32.dll", "CloseHandle",
                _tsBoolean, new TypeSig[] { _tsIntPtr });

            GetTickCount = BuildResolver("kernel32.dll", "GetTickCount",
                _tsUInt32, new TypeSig[0]);

            GetLastError = BuildResolver("kernel32.dll", "GetLastError",
                _tsUInt32, new TypeSig[0]);

            SetLastError = BuildResolver("kernel32.dll", "SetLastError",
                module.CorLibTypes.Void, new TypeSig[] { _tsUInt32 });
        }

        private ModuleRef GetOrCreateModuleRef(string dll)
        {
            foreach (ModuleRef mr in module.GetModuleRefs())
            {
                if (mr.Name == dll) return mr;
            }
            return new ModuleRefUser(module, dll);
        }

        private MethodDef MakeStaticPInvoke(string entryPoint, ModuleRef dllRef, MethodSig sig, DnPInvokeAttributes flags)
        {
            MethodDefUser m = new MethodDefUser(engine.MakeName(),
                sig,
                DnMethodImplAttributes.PreserveSig,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static |
                DnMethodAttributes.PinvokeImpl | DnMethodAttributes.HideBySig);
            m.ImplMap = new ImplMapUser(dllRef, entryPoint, flags);
            container.Methods.Add(m);
            engine.injectedMethods.Add(m);
            return m;
        }

        private FieldDef AddIntPtrField()
        {
            var f = new FieldDefUser(engine.MakeName(),
                new FieldSig(_tsIntPtr),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            container.Fields.Add(f);
            return f;
        }

        private MethodDef BuildDecryptHelper()
        {
            Importer importer = new Importer(module);
            IMethod strCtor = importer.Import(typeof(string).GetConstructor(new Type[] { typeof(char[]) }));

            MethodDefUser m = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(_tsString, new SZArraySig(module.CorLibTypes.Byte)),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            m.Body.InitLocals = true;
            m.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Char)));
            m.Body.Variables.Add(new Local(_tsInt32));

            IList<Instruction> il = m.Body.Instructions;

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
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)_xorKey));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
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

            container.Methods.Add(m);
            engine.injectedMethods.Add(m);
            return m;
        }

        private MethodDef BuildResolver(string dll, string entryPoint, TypeSig retType, TypeSig[] paramTypes)
        {

            FieldDef ptrField = AddIntPtrField();

            FieldDef dllHandleField = (dll == "ntdll.dll") ? _hNtdll : _hKernel32;

            MethodSig managedSig = MethodSig.CreateStatic(retType, paramTypes);

            MethodDefUser m = new MethodDefUser(engine.MakeName(),
                managedSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            m.Body.InitLocals = true;
            IList<Instruction> il = m.Body.Instructions;

            Instruction afterResolve = Instruction.Create(DnOpCodes.Nop);
            Instruction afterDllLoad = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, ptrField));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld,
                ImportField(typeof(IntPtr).GetField("Zero"))));
            il.Add(Instruction.Create(DnOpCodes.Call,
                ImportMethod(typeof(IntPtr).GetMethod("op_Inequality",
                    new Type[] { typeof(IntPtr), typeof(IntPtr) }))));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, afterResolve));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, dllHandleField));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld,
                ImportField(typeof(IntPtr).GetField("Zero"))));
            il.Add(Instruction.Create(DnOpCodes.Call,
                ImportMethod(typeof(IntPtr).GetMethod("op_Inequality",
                    new Type[] { typeof(IntPtr), typeof(IntPtr) }))));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, afterDllLoad));

            EmitEncryptedBytes(il, dll);
            il.Add(Instruction.Create(DnOpCodes.Call, _decryptString));
            il.Add(Instruction.Create(DnOpCodes.Call, _pLoadLibraryA));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, dllHandleField));
            il.Add(afterDllLoad);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, dllHandleField));
            EmitEncryptedBytes(il, entryPoint);
            il.Add(Instruction.Create(DnOpCodes.Call, _decryptString));
            il.Add(Instruction.Create(DnOpCodes.Call, _pGetProcAddress));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, ptrField));

            il.Add(afterResolve);

            Instruction beginCall = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, ptrField));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld,
                ImportField(typeof(IntPtr).GetField("Zero"))));
            il.Add(Instruction.Create(DnOpCodes.Call,
                ImportMethod(typeof(IntPtr).GetMethod("op_Inequality",
                    new Type[] { typeof(IntPtr), typeof(IntPtr) }))));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, beginCall));

            EmitDefaultReturn(il, retType);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(beginCall);

            for (int i = 0; i < paramTypes.Length; i++)
            {
                if (i == 0) il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                else if (i == 1) il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                else if (i == 2) il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
                else if (i == 3) il.Add(Instruction.Create(DnOpCodes.Ldarg_3));
                else il.Add(Instruction.Create(DnOpCodes.Ldarg_S, m.Parameters[i]));
            }

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, ptrField));

            MethodSig nativeSig = new MethodSig(DnCallingConvention.StdCall, 0, retType, paramTypes);
            il.Add(Instruction.Create(DnOpCodes.Calli, nativeSig));

            il.Add(Instruction.Create(DnOpCodes.Ret));

            container.Methods.Add(m);
            engine.injectedMethods.Add(m);
            return m;
        }

        private void EmitEncryptedBytes(IList<Instruction> il, string s)
        {
            byte[] enc = new byte[s.Length];
            for (int i = 0; i < s.Length; i++)
                enc[i] = (byte)((byte)s[i] ^ _xorKey ^ (byte)(i & 0xFF));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, enc.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            for (int i = 0; i < enc.Length; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)enc[i]));
                il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
            }
        }

        private IField ImportField(System.Reflection.FieldInfo fi)
        {
            return new Importer(module).Import(fi);
        }

        private IMethod ImportMethod(System.Reflection.MethodBase mi)
        {
            return new Importer(module).Import(mi);
        }

        private void EmitDefaultReturn(IList<Instruction> il, TypeSig retType)
        {
            ElementType et = retType.ElementType;

            if (et == ElementType.Void) return;

            if (retType.FullName == "System.IntPtr" || retType.FullName == "System.UIntPtr")
            {
                il.Add(Instruction.Create(DnOpCodes.Ldsfld,
                    ImportField(typeof(IntPtr).GetField("Zero"))));
                return;
            }

            if (et == ElementType.Boolean ||
                et == ElementType.I1 || et == ElementType.U1 ||
                et == ElementType.I2 || et == ElementType.U2 ||
                et == ElementType.I4 || et == ElementType.U4 ||
                et == ElementType.Char)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                return;
            }

            if (et == ElementType.I8 || et == ElementType.U8)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                il.Add(Instruction.Create(DnOpCodes.Conv_I8));
                return;
            }

            if (et == ElementType.R4)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_R4, 0.0f));
                return;
            }

            if (et == ElementType.R8)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_R8, 0.0));
                return;
            }

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Conv_I));
        }

    }
}

