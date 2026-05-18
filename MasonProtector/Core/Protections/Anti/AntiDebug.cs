using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class AntiDebugProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const ulong FNV_OFFSET = 0xcbf29ce484222325UL;
        private const long FNV_PRIME = 0x100000001b3L;

        private static readonly string[] blockedNames = new string[]
        {
            "dnspy", "ilspy", "ilspycmd",
            "x64dbg", "x32dbg", "x96dbg", "x64dbgide",
            "ollydbg", "windbg",
            "de4dot", "de4dotex",
            "megadumper", "extremedumper",
            "cheatengine",
            "scylla", "scyllahide", "scyllahook",
            "lordpe", "petools", "reflexil",
            "httpdebugger",
            "frida", "fridaserver", "fridaagent", "fridacore",
            "vmunpack", "dotnetspy",
            "easyhook", "minhook",
            "vehdebugger", "ttdrecord",
        };

        internal AntiDebugProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiDebug(ModuleDef module, TypeDef modType)
        {
            TypeDef antiType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            antiType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(antiType);
            engine.injectedTypes.Add(antiType);

            byte[] salt = engine.CryptoRandom(16);
            byte[] xorMask = engine.CryptoRandom(24);

            HashSet<ulong> uniqueHashes = new HashSet<ulong>();
            ulong prefixHash = ComputePrefixHash(salt);
            foreach (string name in blockedNames)
                AddWholeWordHash(uniqueHashes, prefixHash, name);

            int decoyCount = rng.Next(40, 90);
            for (int i = 0; i < decoyCount; i++)
            {
                ulong fake;
                do { fake = ((ulong)(uint)rng.Next() << 32) | (ulong)(uint)rng.Next(); }
                while (uniqueHashes.Contains(fake));
                uniqueHashes.Add(fake);
            }

            List<ulong> ordered = uniqueHashes.ToList();
            for (int i = ordered.Count - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                ulong t = ordered[i]; ordered[i] = ordered[j]; ordered[j] = t;
            }

            byte[] encHashes = new byte[ordered.Count * 8];
            for (int i = 0; i < ordered.Count; i++)
            {
                ulong v = ordered[i];
                for (int j = 0; j < 8; j++)
                {
                    byte plain = (byte)((v >> (j * 8)) & 0xFF);
                    int maskIdx = (i * 8 + j) % xorMask.Length;
                    encHashes[i * 8 + j] = (byte)(plain ^ xorMask[maskIdx]);
                }
            }

            MethodDef cctor = new MethodDefUser(".cctor",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static |
                DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                DnMethodAttributes.RTSpecialName);
            cctor.Body = new CilBody();
            cctor.Body.InitLocals = true;
            cctor.Body.Variables.Add(new Local(module.CorLibTypes.UInt64));
            cctor.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            antiType.Methods.Add(cctor);
            engine.injectedMethods.Add(cctor);

            FieldDef saltField    = EmitRvaArrayField(module, antiType, cctor.Body.Instructions, salt);
            FieldDef xorMaskField = EmitRvaArrayField(module, antiType, cctor.Body.Instructions, xorMask);
            FieldDef encHashField = EmitRvaArrayField(module, antiType, cctor.Body.Instructions, encHashes);

            FieldDef prefixHashField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.UInt64),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            antiType.Fields.Add(prefixHashField);

            EmitPrefixHashCompute(module, cctor.Body.Instructions, saltField, prefixHashField);
            cctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            cctor.Body.KeepOldMaxStack = false;

            NativeShroud shroud = new NativeShroud(engine, module, antiType);
            shroud.Build();
            engine.antiShroud = shroud;

            MethodDef hashRangeMethod = BuildHashRangeMethod(module, antiType, prefixHashField);
            MethodDef containsMethod  = BuildContainsMethod(module, antiType, encHashField, xorMaskField);
            MethodDef suicideMethod   = BuildSuicideMethod(module, antiType, shroud);
            MethodDef scanStringMethod= BuildScanStringMethod(module, antiType, hashRangeMethod, containsMethod, suicideMethod);
            MethodDef scanModulesMethod = BuildScanLoadedModulesMethod(module, antiType, scanStringMethod, shroud);
            MethodDef scanOne         = BuildScanOneProcessMethod(module, antiType, scanStringMethod);
            MethodDef processScanner  = BuildProcessScannerMethod(module, antiType, scanOne);

            antiType.Methods.Add(hashRangeMethod);
            antiType.Methods.Add(containsMethod);
            antiType.Methods.Add(suicideMethod);
            antiType.Methods.Add(scanStringMethod);
            antiType.Methods.Add(scanModulesMethod);
            antiType.Methods.Add(scanOne);
            antiType.Methods.Add(processScanner);
            engine.injectedMethods.Add(hashRangeMethod);
            engine.injectedMethods.Add(containsMethod);
            engine.injectedMethods.Add(suicideMethod);
            engine.injectedMethods.Add(scanStringMethod);
            engine.injectedMethods.Add(scanModulesMethod);
            engine.injectedMethods.Add(scanOne);
            engine.injectedMethods.Add(processScanner);

            MethodDef debugCheckMethod = BuildDebugCheckMethod(module, antiType, shroud, suicideMethod);
            antiType.Methods.Add(debugCheckMethod);
            engine.injectedMethods.Add(debugCheckMethod);

            MethodDef initMethod = BuildInitMethod(module, antiType,
                scanModulesMethod, processScanner, suicideMethod, debugCheckMethod);
            antiType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);
            engine.InjectCallAtTop(module, modType, initMethod);

            MethodDef bgThread = BuildBackgroundMonitorMethod(module, antiType,
                scanModulesMethod, processScanner, suicideMethod, debugCheckMethod);
            antiType.Methods.Add(bgThread);
            engine.injectedMethods.Add(bgThread);

            MethodDef startBg = BuildStartBackgroundMethod(module, antiType, bgThread);
            antiType.Methods.Add(startBg);
            engine.injectedMethods.Add(startBg);
            engine.InjectCallInCctor(module, modType, startBg);
        }

        private MethodDef BuildDebugCheckMethod(ModuleDef module, TypeDef owner,
            NativeShroud shroud, MethodDef suicide)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.IntPtr));
            method.Body.Variables.Add(new Local(module.CorLibTypes.UInt32));

            IList<Instruction> il = method.Body.Instructions;
            Instruction retInst = Instruction.Create(DnOpCodes.Ret);
            Instruction afterIsDbg = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Call, shroud.IsDebuggerPresent));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, afterIsDbg));
            il.Add(Instruction.Create(DnOpCodes.Call, suicide));
            il.Add(afterIsDbg);

            Instruction afterRemote = Instruction.Create(DnOpCodes.Nop);
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
            il.Add(Instruction.Create(DnOpCodes.Ldloca_S, method.Body.Variables[0]));
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.CheckRemoteDebuggerPresent));
            il.Add(Instruction.Create(DnOpCodes.Pop));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, afterRemote));
            il.Add(Instruction.Create(DnOpCodes.Call, suicide));
            il.Add(afterRemote);

            Instruction afterNt = Instruction.Create(DnOpCodes.Nop);
            Instruction ntTryStart = Instruction.Create(DnOpCodes.Ldc_I4_8);
            il.Add(ntTryStart);

            il.Add(Instruction.Create(DnOpCodes.Localloc));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Stind_I8));

            il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_7));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_8));
            il.Add(Instruction.Create(DnOpCodes.Ldloca_S, method.Body.Variables[2]));
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.NtQueryInformationProcess));
            il.Add(Instruction.Create(DnOpCodes.Pop));

            Instruction noDebugger = Instruction.Create(DnOpCodes.Leave, afterNt);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldind_I8));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Beq, noDebugger));

            il.Add(Instruction.Create(DnOpCodes.Call, suicide));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterNt));

            il.Add(noDebugger);

            Instruction ntCatch = Instruction.Create(DnOpCodes.Pop);
            il.Add(ntCatch);
            il.Add(Instruction.Create(DnOpCodes.Leave, afterNt));
            il.Add(afterNt);

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = ntTryStart,
                TryEnd = ntCatch,
                HandlerStart = ntCatch,
                HandlerEnd = afterNt,
                CatchType = new TypeRefUser(module, "System", "Exception",
                    module.CorLibTypes.AssemblyRef)
            });

            il.Add(retInst);
            return method;
        }

        private static ulong ComputePrefixHash(byte[] salt)
        {
            ulong h = FNV_OFFSET;
            for (int i = 0; i < salt.Length; i++)
            {
                h ^= salt[i];
                h *= (ulong)FNV_PRIME;
            }
            return h;
        }

        private static void AddWholeWordHash(HashSet<ulong> set, ulong prefix, string name)
        {
            if (string.IsNullOrEmpty(name)) return;
            string canonical = Canonicalize(name);
            if (canonical.Length < 4) return;
            byte[] data = Encoding.ASCII.GetBytes(canonical);
            ulong h = prefix;
            for (int i = 0; i < data.Length; i++)
            {
                h = (h ^ data[i]) * (ulong)FNV_PRIME;
            }
            set.Add(h);
        }

        private static string Canonicalize(string name)
        {
            StringBuilder sb = new StringBuilder(name.Length);
            foreach (char c in name.ToLowerInvariant())
            {
                if (IsSeparatorChar(c)) continue;
                sb.Append(c);
            }
            return sb.ToString();
        }

        private static bool IsSeparatorChar(char c)
        {
            return c == ' ' || c == '.' || c == '_' || c == '-'
                || c == '/' || c == '\\' || c == ':' || c == '+'
                || c == '(' || c == ')' || c == '[' || c == ']'
                || c == ',' || c == ';' || c == '!' || c == '\t'
                || c <= 31;
        }

        private FieldDef EmitRvaArrayField(ModuleDef module, TypeDef owner,
            IList<Instruction> cctorIl, byte[] bytes)
        {
            Importer importer = new Importer(module);
            ITypeDefOrRef sysValueType = importer.Import(typeof(ValueType));
            ITypeDefOrRef sysByte = importer.Import(typeof(byte));
            IMethod rhInitArr = importer.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers)
                .GetMethod("InitializeArray",
                    new Type[] { typeof(Array), typeof(RuntimeFieldHandle) }));

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

            FieldDef arrField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            owner.Fields.Add(arrField);

            cctorIl.Add(engine.LoadInt(bytes.Length));
            cctorIl.Add(Instruction.Create(DnOpCodes.Newarr, sysByte));
            cctorIl.Add(Instruction.Create(DnOpCodes.Dup));
            cctorIl.Add(Instruction.Create(DnOpCodes.Ldtoken, rvaField));
            cctorIl.Add(Instruction.Create(DnOpCodes.Call, rhInitArr));
            cctorIl.Add(Instruction.Create(DnOpCodes.Stsfld, arrField));

            return arrField;
        }

        private void EmitPrefixHashCompute(ModuleDef module, IList<Instruction> il,
            FieldDef saltField, FieldDef prefixHashField)
        {
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, unchecked((long)FNV_OFFSET)));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            Instruction loopStart = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            Instruction loopBody = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, saltField));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Conv_U8));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, FNV_PRIME));
            il.Add(Instruction.Create(DnOpCodes.Mul));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, saltField));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, prefixHashField));
        }

        private MethodDef BuildHashRangeMethod(ModuleDef module, TypeDef owner, FieldDef prefixHashField)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.UInt64,
                    new SZArraySig(module.CorLibTypes.Byte),
                    module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.UInt64));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            IList<Instruction> il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, prefixHashField));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            Instruction loopStart = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            Instruction loopBody = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Conv_U8));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, FNV_PRIME));
            il.Add(Instruction.Create(DnOpCodes.Mul));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildContainsMethod(ModuleDef module, TypeDef owner,
            FieldDef encHashField, FieldDef xorMaskField)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.UInt64),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.UInt64));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            IList<Instruction> il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, xorMaskField));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            Instruction outerStart = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Br, outerStart));

            Instruction outerBody = Instruction.Create(DnOpCodes.Ldc_I4_0);
            il.Add(outerBody);
            il.Add(Instruction.Create(DnOpCodes.Conv_U8));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            Instruction innerStart = Instruction.Create(DnOpCodes.Ldloc_2);
            il.Add(Instruction.Create(DnOpCodes.Br, innerStart));

            Instruction innerBody = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(innerBody);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, encHashField));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, xorMaskField));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Rem));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));

            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Conv_U8));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_3));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0x3F));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(innerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_8));
            il.Add(Instruction.Create(DnOpCodes.Blt, innerBody));

            Instruction afterCheck = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Bne_Un, afterCheck));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(afterCheck);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_8));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(outerStart);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, encHashField));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_8));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ble, outerBody));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildSuicideMethod(ModuleDef module, TypeDef owner, NativeShroud shroud)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;

            ITypeDefOrRef objectType = module.CorLibTypes.Object.TypeDefOrRef;

            IList<Instruction> il = method.Body.Instructions;

            if (engine.antiCrackOnDetection != null)
            {
                Instruction acTryStart = Instruction.Create(DnOpCodes.Call, engine.antiCrackOnDetection);
                il.Add(acTryStart);
                Instruction acHandlerEnd = Instruction.Create(DnOpCodes.Nop);
                il.Add(Instruction.Create(DnOpCodes.Leave, acHandlerEnd));
                Instruction acHandlerStart = Instruction.Create(DnOpCodes.Pop);
                il.Add(acHandlerStart);
                il.Add(Instruction.Create(DnOpCodes.Leave, acHandlerEnd));
                il.Add(acHandlerEnd);
                method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                {
                    TryStart     = acTryStart,
                    TryEnd       = acHandlerStart,
                    HandlerStart = acHandlerStart,
                    HandlerEnd   = acHandlerEnd,
                    CatchType    = objectType,
                });
            }

            int[] order = new int[] { 0, 1, 2, 3, 4 };
            for (int i = order.Length - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                int t = order[i]; order[i] = order[j]; order[j] = t;
            }

            foreach (int phase in order)
            {
                int tryStartIdx = il.Count;
                EmitKillPhase(il, phase, shroud);
                Instruction tryStart = il[tryStartIdx];

                Instruction handlerEnd = Instruction.Create(DnOpCodes.Nop);
                il.Add(Instruction.Create(DnOpCodes.Leave, handlerEnd));
                Instruction handlerStart = Instruction.Create(DnOpCodes.Pop);
                il.Add(handlerStart);
                il.Add(Instruction.Create(DnOpCodes.Leave, handlerEnd));
                il.Add(handlerEnd);

                method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                {
                    TryStart = tryStart,
                    TryEnd = handlerStart,
                    HandlerStart = handlerStart,
                    HandlerEnd = handlerEnd,
                    CatchType = objectType
                });
            }

            il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
            il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
            il.Add(Instruction.Create(DnOpCodes.Pop));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private void EmitKillPhase(IList<Instruction> il, int phase, NativeShroud shroud)
        {

            switch (phase)
            {
                case 0:
                    il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
                    il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 1:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
                    il.Add(Instruction.Create(DnOpCodes.Call, shroud.ExitProcess));
                    break;
                case 2:

                    il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, -3));
                    il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
                case 3:

                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, -4));
                    il.Add(Instruction.Create(DnOpCodes.Call, shroud.ExitProcess));
                    break;
                case 4:
                    il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, -2));
                    il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    break;
            }
        }

        private MethodDef BuildScanStringMethod(ModuleDef module, TypeDef owner,
            MethodDef hashRangeMethod, MethodDef containsMethod, MethodDef suicideMethod)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.String));
            method.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.UInt64));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

            Importer importer = new Importer(module);
            IMethod toLower = importer.Import(typeof(string).GetMethod("ToLowerInvariant", Type.EmptyTypes));
            IMethod getChars = importer.Import(typeof(string).GetMethod("get_Chars", new Type[] { typeof(int) }));
            IMethod getLength = importer.Import(typeof(string).GetProperty("Length").GetGetMethod());

            IList<Instruction> il = method.Body.Instructions;
            Instruction retInst = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, retInst));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, toLower));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getLength));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[5]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[5]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_4));
            il.Add(Instruction.Create(DnOpCodes.Blt, retInst));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[5]));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[9]));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[4]));

            Instruction loopCond = Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[4]);
            il.Add(Instruction.Create(DnOpCodes.Br, loopCond));

            Instruction loopBody = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[4]));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getChars));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[6]));

            Instruction notSep = Instruction.Create(DnOpCodes.Nop);
            EmitIsSeparatorCheck(il, method, notSep);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[9]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[8]));

            Instruction skipToken = Instruction.Create(DnOpCodes.Ldloc_2);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[8]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_4));
            il.Add(Instruction.Create(DnOpCodes.Blt, skipToken));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[8]));
            il.Add(Instruction.Create(DnOpCodes.Call, hashRangeMethod));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[7]));

            Instruction skipKill1 = Instruction.Create(DnOpCodes.Nop);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[7]));
            il.Add(Instruction.Create(DnOpCodes.Call, containsMethod));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, skipKill1));
            il.Add(Instruction.Create(DnOpCodes.Call, suicideMethod));
            il.Add(skipKill1);

            il.Add(skipToken);
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            Instruction nextIter = Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[4]);
            il.Add(Instruction.Create(DnOpCodes.Br, nextIter));

            il.Add(notSep);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[6]));
            il.Add(Instruction.Create(DnOpCodes.Conv_U1));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(nextIter);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[4]));

            il.Add(loopCond);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[5]));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[8]));

            Instruction skipFinalToken = Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[9]);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[8]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_4));
            il.Add(Instruction.Create(DnOpCodes.Blt, skipFinalToken));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[8]));
            il.Add(Instruction.Create(DnOpCodes.Call, hashRangeMethod));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[7]));

            Instruction skipKill2 = Instruction.Create(DnOpCodes.Nop);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[7]));
            il.Add(Instruction.Create(DnOpCodes.Call, containsMethod));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, skipKill2));
            il.Add(Instruction.Create(DnOpCodes.Call, suicideMethod));
            il.Add(skipKill2);

            il.Add(skipFinalToken);
            il.Add(Instruction.Create(DnOpCodes.Brfalse, retInst));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_4));
            il.Add(Instruction.Create(DnOpCodes.Blt, retInst));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Call, hashRangeMethod));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[7]));

            Instruction skipKill3 = Instruction.Create(DnOpCodes.Nop);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[7]));
            il.Add(Instruction.Create(DnOpCodes.Call, containsMethod));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, skipKill3));
            il.Add(Instruction.Create(DnOpCodes.Call, suicideMethod));
            il.Add(skipKill3);

            il.Add(retInst);
            return method;
        }

        private void EmitIsSeparatorCheck(IList<Instruction> il, MethodDef method, Instruction notSepTarget)
        {
            int[] separators = new int[] {
                ' ', '.', '_', '-', '/', '\\', ':', '+',
                '(', ')', '[', ']', ',', ';', '!', '\t'
            };
            Instruction isSep = Instruction.Create(DnOpCodes.Nop);
            for (int i = 0; i < separators.Length; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[6]));
                il.Add(engine.LoadInt(separators[i]));
                il.Add(Instruction.Create(DnOpCodes.Beq, isSep));
            }
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[6]));
            il.Add(engine.LoadInt(32));
            il.Add(Instruction.Create(DnOpCodes.Blt, isSep));
            il.Add(Instruction.Create(DnOpCodes.Br, notSepTarget));
            il.Add(isSep);
        }

        private MethodDef BuildScanLoadedModulesMethod(ModuleDef module, TypeDef owner,
            MethodDef scanString, NativeShroud shroud)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;

            Importer importer = new Importer(module);
            IMethod getCurrent = importer.Import(typeof(System.Diagnostics.Process).GetMethod("GetCurrentProcess", Type.EmptyTypes));
            IMethod getModules = importer.Import(typeof(System.Diagnostics.Process).GetProperty("Modules").GetGetMethod());
            IMethod modulesCount = importer.Import(typeof(System.Diagnostics.ProcessModuleCollection).GetProperty("Count").GetGetMethod());
            IMethod modulesItem = importer.Import(typeof(System.Diagnostics.ProcessModuleCollection).GetMethod("get_Item", new Type[] { typeof(int) }));
            IMethod moduleName = importer.Import(typeof(System.Diagnostics.ProcessModule).GetProperty("ModuleName").GetGetMethod());

            method.Body.Variables.Add(new Local(importer.Import(typeof(System.Diagnostics.ProcessModuleCollection)).ToTypeSig()));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            IList<Instruction> il = method.Body.Instructions;
            Instruction retInst = Instruction.Create(DnOpCodes.Ret);
            Instruction outerCatch = Instruction.Create(DnOpCodes.Pop);

            Instruction tryStart = Instruction.Create(DnOpCodes.Call, getCurrent);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getModules));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, modulesCount));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            Instruction loopCond = Instruction.Create(DnOpCodes.Ldloc_2);
            il.Add(Instruction.Create(DnOpCodes.Br, loopCond));

            Instruction iterEnd = Instruction.Create(DnOpCodes.Ldloc_2);
            Instruction innerTryStart = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(innerTryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, modulesItem));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, moduleName));
            il.Add(Instruction.Create(DnOpCodes.Call, scanString));
            il.Add(Instruction.Create(DnOpCodes.Leave, iterEnd));

            Instruction innerCatch = Instruction.Create(DnOpCodes.Pop);
            il.Add(innerCatch);
            il.Add(Instruction.Create(DnOpCodes.Leave, iterEnd));

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = innerTryStart,
                TryEnd = innerCatch,
                HandlerStart = innerCatch,
                HandlerEnd = iterEnd,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            il.Add(iterEnd);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(loopCond);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Blt, innerTryStart));

            il.Add(Instruction.Create(DnOpCodes.Leave, retInst));
            il.Add(outerCatch);
            il.Add(Instruction.Create(DnOpCodes.Leave, retInst));
            il.Add(retInst);

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = outerCatch,
                HandlerStart = outerCatch,
                HandlerEnd = retInst,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return method;
        }

        private MethodDef BuildScanOneProcessMethod(ModuleDef module, TypeDef owner, MethodDef scanString)
        {
            TypeSig processSig = module.Import(typeof(System.Diagnostics.Process)).ToTypeSig();
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, processSig),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.Import(typeof(System.Diagnostics.FileVersionInfo)).ToTypeSig()));

            Importer importer = new Importer(module);
            IMethod getProcName = importer.Import(typeof(System.Diagnostics.Process).GetProperty("ProcessName").GetGetMethod());
            IMethod getMainModule = importer.Import(typeof(System.Diagnostics.Process).GetProperty("MainModule").GetGetMethod());
            IMethod getFvi = importer.Import(typeof(System.Diagnostics.ProcessModule).GetProperty("FileVersionInfo").GetGetMethod());
            IMethod getOrigName = importer.Import(typeof(System.Diagnostics.FileVersionInfo).GetProperty("OriginalFilename").GetGetMethod());
            IMethod getFileDesc = importer.Import(typeof(System.Diagnostics.FileVersionInfo).GetProperty("FileDescription").GetGetMethod());
            IMethod getProdName = importer.Import(typeof(System.Diagnostics.FileVersionInfo).GetProperty("ProductName").GetGetMethod());
            IMethod getInternalName = importer.Import(typeof(System.Diagnostics.FileVersionInfo).GetProperty("InternalName").GetGetMethod());
            IMethod getCompName = importer.Import(typeof(System.Diagnostics.FileVersionInfo).GetProperty("CompanyName").GetGetMethod());
            IMethod getMainWindowTitle = importer.Import(typeof(System.Diagnostics.Process).GetProperty("MainWindowTitle").GetGetMethod());

            IList<Instruction> il = method.Body.Instructions;
            Instruction retInst = Instruction.Create(DnOpCodes.Ret);

            EmitTryScanProcStringProp(il, getProcName, scanString, method, module);

            Instruction stage2Start = Instruction.Create(DnOpCodes.Ldarg_0);
            Instruction stage2End = Instruction.Create(DnOpCodes.Nop);

            il.Add(stage2Start);
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getMainModule));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getFvi));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            IMethod[] fviProps = new IMethod[] { getOrigName, getFileDesc, getProdName, getInternalName, getCompName };
            foreach (IMethod p in fviProps)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Callvirt, p));
                il.Add(Instruction.Create(DnOpCodes.Call, scanString));
            }

            il.Add(Instruction.Create(DnOpCodes.Leave, stage2End));
            Instruction stage2Catch = Instruction.Create(DnOpCodes.Pop);
            il.Add(stage2Catch);
            il.Add(Instruction.Create(DnOpCodes.Leave, stage2End));
            il.Add(stage2End);

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = stage2Start,
                TryEnd = stage2Catch,
                HandlerStart = stage2Catch,
                HandlerEnd = stage2End,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            EmitTryScanProcStringProp(il, getMainWindowTitle, scanString, method, module);

            il.Add(retInst);
            return method;
        }

        private void EmitTryScanProcStringProp(IList<Instruction> il, IMethod getter,
            MethodDef scanString, MethodDef ownerMethod, ModuleDef module)
        {
            Instruction tryStart = Instruction.Create(DnOpCodes.Ldarg_0);
            Instruction tryEnd = Instruction.Create(DnOpCodes.Nop);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getter));
            il.Add(Instruction.Create(DnOpCodes.Call, scanString));
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));
            Instruction catchInst = Instruction.Create(DnOpCodes.Pop);
            il.Add(catchInst);
            il.Add(Instruction.Create(DnOpCodes.Leave, tryEnd));
            il.Add(tryEnd);

            ownerMethod.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = catchInst,
                HandlerStart = catchInst,
                HandlerEnd = tryEnd,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });
        }

        private MethodDef BuildProcessScannerMethod(ModuleDef module, TypeDef owner, MethodDef scanOne)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;

            TypeSig procArrSig = module.Import(typeof(System.Diagnostics.Process[])).ToTypeSig();
            method.Body.Variables.Add(new Local(procArrSig));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            Importer importer = new Importer(module);
            IMethod getProcesses = importer.Import(typeof(System.Diagnostics.Process).GetMethod("GetProcesses", Type.EmptyTypes));

            IList<Instruction> il = method.Body.Instructions;
            Instruction retInst = Instruction.Create(DnOpCodes.Ret);

            Instruction tryStart = Instruction.Create(DnOpCodes.Call, getProcesses);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            Instruction loopStart = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            Instruction iterEnd = Instruction.Create(DnOpCodes.Ldloc_1);
            Instruction innerTry = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(innerTry);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Call, scanOne));
            il.Add(Instruction.Create(DnOpCodes.Leave, iterEnd));
            Instruction innerCatch = Instruction.Create(DnOpCodes.Pop);
            il.Add(innerCatch);
            il.Add(Instruction.Create(DnOpCodes.Leave, iterEnd));

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = innerTry,
                TryEnd = innerCatch,
                HandlerStart = innerCatch,
                HandlerEnd = iterEnd,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            il.Add(iterEnd);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Blt, innerTry));

            il.Add(Instruction.Create(DnOpCodes.Leave, retInst));
            Instruction outerCatch = Instruction.Create(DnOpCodes.Pop);
            il.Add(outerCatch);
            il.Add(Instruction.Create(DnOpCodes.Leave, retInst));
            il.Add(retInst);

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = outerCatch,
                HandlerStart = outerCatch,
                HandlerEnd = retInst,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return method;
        }

        private MethodDef BuildInitMethod(ModuleDef module, TypeDef owner,
            MethodDef scanModules, MethodDef processScanner, MethodDef suicide,
            MethodDef debugCheckMethod)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;

            IList<Instruction> il = method.Body.Instructions;
            Instruction retInst = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Call, debugCheckMethod));
            il.Add(Instruction.Create(DnOpCodes.Call, scanModules));
            il.Add(Instruction.Create(DnOpCodes.Call, processScanner));
            il.Add(retInst);

            return method;
        }

        private MethodDef BuildBackgroundMonitorMethod(ModuleDef module, TypeDef owner,
            MethodDef scanModules, MethodDef processScanner, MethodDef suicide,
            MethodDef debugCheckMethod)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;

            Importer importer = new Importer(module);
            IMethod threadSleep = importer.Import(typeof(System.Threading.Thread).GetMethod("Sleep", new Type[] { typeof(int) }));

            IList<Instruction> il = method.Body.Instructions;

            Instruction loopHead = Instruction.Create(DnOpCodes.Nop);
            Instruction tryStart = Instruction.Create(DnOpCodes.Call, debugCheckMethod);
            Instruction sleepInst = Instruction.Create(DnOpCodes.Ldc_I4, 1500 + rng.Next(0, 2500));

            il.Add(loopHead);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Call, scanModules));
            il.Add(Instruction.Create(DnOpCodes.Call, processScanner));
            il.Add(Instruction.Create(DnOpCodes.Leave, sleepInst));

            Instruction handlerStart = Instruction.Create(DnOpCodes.Pop);
            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Leave, sleepInst));

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = sleepInst,
                CatchType = new TypeRefUser(module, "System", "Exception",
                    module.CorLibTypes.AssemblyRef)
            });

            il.Add(sleepInst);
            il.Add(Instruction.Create(DnOpCodes.Call, threadSleep));
            il.Add(Instruction.Create(DnOpCodes.Br, loopHead));

            return method;
        }

        private MethodDef BuildStartBackgroundMethod(ModuleDef module, TypeDef owner, MethodDef bgThread)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.Import(typeof(System.Threading.Thread)).ToTypeSig()));

            Importer importer = new Importer(module);
            IMethod threadStartCtor = importer.Import(typeof(System.Threading.ThreadStart).GetConstructor(
                new Type[] { typeof(object), typeof(IntPtr) }));
            IMethod threadCtor = importer.Import(typeof(System.Threading.Thread).GetConstructor(
                new Type[] { typeof(System.Threading.ThreadStart) }));
            IMethod threadSetBg = importer.Import(typeof(System.Threading.Thread).GetProperty("IsBackground").GetSetMethod());
            IMethod threadStart = importer.Import(typeof(System.Threading.Thread).GetMethod("Start", Type.EmptyTypes));

            IList<Instruction> il = method.Body.Instructions;
            Instruction retInst = Instruction.Create(DnOpCodes.Ret);

            Instruction tryStart = Instruction.Create(DnOpCodes.Ldnull);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldftn, bgThread));
            il.Add(Instruction.Create(DnOpCodes.Newobj, threadStartCtor));
            il.Add(Instruction.Create(DnOpCodes.Newobj, threadCtor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, threadSetBg));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, threadStart));
            il.Add(Instruction.Create(DnOpCodes.Leave, retInst));

            Instruction catchInst = Instruction.Create(DnOpCodes.Pop);
            il.Add(catchInst);
            il.Add(Instruction.Create(DnOpCodes.Leave, retInst));
            il.Add(retInst);

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = catchInst,
                HandlerStart = catchInst,
                HandlerEnd = retInst,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return method;
        }
    }
}

