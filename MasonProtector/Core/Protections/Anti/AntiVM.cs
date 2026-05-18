using System;
using System.Collections.Generic;
using System.Linq;
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
    internal class AntiVMProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const ulong FNV_OFFSET = 0xcbf29ce484222325UL;
        private const long FNV_PRIME = 0x100000001b3L;

        private static readonly string[] vmProcesses = new string[]
        {
            "qemuga", "prltools", "prlcc",
            "xenservice", "joeboxcontrol", "joeboxserver",
            "vmusrvc", "vmsrvc", "xenstore", "xenmgmt"
        };

        internal AntiVMProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiVM(ModuleDef module, TypeDef modType)
        {
            var vmType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vmType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(vmType);
            engine.injectedTypes.Add(vmType);

            byte[] salt = engine.CryptoRandom(16);
            byte[] xorMask = engine.CryptoRandom(24);

            HashSet<ulong> uniqueHashes = new HashSet<ulong>();
            ulong prefixHash = ComputePrefixHash(salt);
            foreach (string name in vmProcesses)
                AddHash(uniqueHashes, prefixHash, name);

            int decoyCount = rng.Next(25, 60);
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
            vmType.Methods.Add(cctor);
            engine.injectedMethods.Add(cctor);

            FieldDef saltField    = EmitRvaArrayField(module, vmType, cctor.Body.Instructions, salt);
            FieldDef xorMaskField = EmitRvaArrayField(module, vmType, cctor.Body.Instructions, xorMask);
            FieldDef encHashField = EmitRvaArrayField(module, vmType, cctor.Body.Instructions, encHashes);

            FieldDef prefixHashField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.UInt64),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vmType.Fields.Add(prefixHashField);

            EmitPrefixHashCompute(module, cctor.Body.Instructions, saltField, prefixHashField, cctor);
            cctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            cctor.Body.KeepOldMaxStack = false;

            NativeShroud shroud = engine.EnsureShroud(module);

            MethodDef containsMethod = BuildContainsMethod(module, vmType, encHashField, xorMaskField);
            MethodDef hashStringMethod = BuildHashStringMethod(module, vmType, prefixHashField);
            MethodDef suicideMethod = BuildSuicideMethod(module, vmType, shroud);
            MethodDef vmCheckMethod = BuildVmScanMethod(module, vmType, hashStringMethod, containsMethod, suicideMethod);

            vmType.Methods.Add(containsMethod);
            vmType.Methods.Add(hashStringMethod);
            vmType.Methods.Add(suicideMethod);
            vmType.Methods.Add(vmCheckMethod);
            engine.injectedMethods.Add(containsMethod);
            engine.injectedMethods.Add(hashStringMethod);
            engine.injectedMethods.Add(suicideMethod);
            engine.injectedMethods.Add(vmCheckMethod);

            engine.InjectCallInCctor(module, modType, vmCheckMethod);

            MethodDef bgVerify = BuildBackgroundVmMonitor(module, vmType, vmCheckMethod);
            vmType.Methods.Add(bgVerify);
            engine.injectedMethods.Add(bgVerify);

            MethodDef startBg = BuildBackgroundStarter(module, vmType, bgVerify);
            vmType.Methods.Add(startBg);
            engine.injectedMethods.Add(startBg);
            engine.InjectCallInCctor(module, modType, startBg);
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

        private static void AddHash(HashSet<ulong> set, ulong prefix, string name)
        {
            if (string.IsNullOrEmpty(name)) return;
            byte[] data = Encoding.ASCII.GetBytes(name.ToLowerInvariant());
            ulong h = prefix;
            for (int i = 0; i < data.Length; i++)
            {
                if (IsSeparatorChar((char)data[i])) continue;
                h = (h ^ data[i]) * (ulong)FNV_PRIME;
            }
            set.Add(h);
        }

        private static bool IsSeparatorChar(char c)
        {
            return c == ' ' || c == '.' || c == '_' || c == '-'
                || c == '/' || c == '\\' || c == ':' || c == '+';
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
            FieldDef saltField, FieldDef prefixHashField, MethodDef cctor)
        {
            cctor.Body.Variables.Add(new Local(module.CorLibTypes.UInt64));
            cctor.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

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

        private MethodDef BuildHashStringMethod(ModuleDef module, TypeDef owner, FieldDef prefixHashField)
        {
            MethodDef method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.UInt64, module.CorLibTypes.String),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.UInt64));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.String));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            Importer importer = new Importer(module);
            IMethod getChars = importer.Import(typeof(string).GetMethod("get_Chars", new Type[] { typeof(int) }));
            IMethod getLength = importer.Import(typeof(string).GetProperty("Length").GetGetMethod());
            IMethod toLower = importer.Import(typeof(string).GetMethod("ToLowerInvariant", Type.EmptyTypes));

            IList<Instruction> il = method.Body.Instructions;
            Instruction retInst = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, prefixHashField));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, retInst));

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, toLower));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getLength));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            Instruction loopCond = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, loopCond));

            Instruction loopBody = Instruction.Create(DnOpCodes.Ldloc_2);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getChars));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[4]));

            Instruction skipChar = Instruction.Create(DnOpCodes.Ldloc_1);
            int[] separators = new int[] { ' ', '.', '_', '-', '/', '\\', ':', '+' };
            for (int i = 0; i < separators.Length; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[4]));
                il.Add(engine.LoadInt(separators[i]));
                il.Add(Instruction.Create(DnOpCodes.Beq, skipChar));
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[4]));
            il.Add(Instruction.Create(DnOpCodes.Conv_U8));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, FNV_PRIME));
            il.Add(Instruction.Create(DnOpCodes.Mul));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(skipChar);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(loopCond);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(retInst);
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

            IList<Instruction> il = method.Body.Instructions;

            engine.EmitAntiCrackHook(il);

            int variant = rng.Next(3);
            if (variant == 0)
            {
                il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
                il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
                il.Add(Instruction.Create(DnOpCodes.Pop));
            }
            else if (variant == 1)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1));
                il.Add(Instruction.Create(DnOpCodes.Call, shroud.ExitProcess));
            }
            else
            {
                il.Add(Instruction.Create(DnOpCodes.Call, shroud.GetCurrentProcess));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, -5));
                il.Add(Instruction.Create(DnOpCodes.Call, shroud.TerminateProcess));
                il.Add(Instruction.Create(DnOpCodes.Pop));
            }

            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildVmScanMethod(ModuleDef module, TypeDef owner,
            MethodDef hashStringMethod, MethodDef containsMethod, MethodDef suicideMethod)
        {
            var vmCheckMethod = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            vmCheckMethod.Body = new CilBody();
            vmCheckMethod.Body.InitLocals = true;

            vmCheckMethod.Body.Variables.Add(new Local(module.Import(typeof(System.Diagnostics.Process[])).ToTypeSig()));
            vmCheckMethod.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            vmCheckMethod.Body.Variables.Add(new Local(module.CorLibTypes.String));
            vmCheckMethod.Body.Variables.Add(new Local(module.CorLibTypes.UInt64));
            vmCheckMethod.Body.Variables.Add(new Local(module.Import(typeof(System.Diagnostics.Process)).ToTypeSig()));

            var il = vmCheckMethod.Body.Instructions;

            var getProcs = module.Import(typeof(System.Diagnostics.Process).GetMethod("GetProcesses", Type.EmptyTypes));
            var getProcName = module.Import(typeof(System.Diagnostics.Process).GetProperty("ProcessName").GetGetMethod());

            var retInst = Instruction.Create(DnOpCodes.Ret);

            var loopBody = Instruction.Create(DnOpCodes.Ldloc_0);
            var loopCond = Instruction.Create(DnOpCodes.Ldloc_1);

            var tryStart = Instruction.Create(DnOpCodes.Call, getProcs);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Br, loopCond));

            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, vmCheckMethod.Body.Variables[4]));

            var innerTry = Instruction.Create(DnOpCodes.Ldloc_S, vmCheckMethod.Body.Variables[4]);
            il.Add(innerTry);
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getProcName));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Call, hashStringMethod));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            var afterContains = Instruction.Create(DnOpCodes.Nop);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Call, containsMethod));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, afterContains));
            il.Add(Instruction.Create(DnOpCodes.Call, suicideMethod));
            il.Add(afterContains);

            var innerEnd = Instruction.Create(DnOpCodes.Nop);
            il.Add(Instruction.Create(DnOpCodes.Leave, innerEnd));
            var innerCatch = Instruction.Create(DnOpCodes.Pop);
            il.Add(innerCatch);
            il.Add(Instruction.Create(DnOpCodes.Leave, innerEnd));
            il.Add(innerEnd);

            vmCheckMethod.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = innerTry,
                TryEnd = innerCatch,
                HandlerStart = innerCatch,
                HandlerEnd = innerEnd,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(loopCond);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Leave, retInst));

            var outerCatch = Instruction.Create(DnOpCodes.Pop);
            il.Add(outerCatch);
            il.Add(Instruction.Create(DnOpCodes.Leave, retInst));

            il.Add(retInst);

            vmCheckMethod.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = outerCatch,
                HandlerStart = outerCatch,
                HandlerEnd = retInst,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            return vmCheckMethod;
        }

        private MethodDef BuildBackgroundVmMonitor(ModuleDef module, TypeDef owner, MethodDef scanner)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();

            var threadSleep = module.Import(typeof(System.Threading.Thread).GetMethod("Sleep", new[] { typeof(int) }));
            var il = method.Body.Instructions;

            var tryStart    = Instruction.Create(DnOpCodes.Call, scanner);
            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            var beforeSleep = Instruction.Create(DnOpCodes.Ldc_I4, 1200 + rng.Next(0, 2400));

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

        private MethodDef BuildBackgroundStarter(ModuleDef module, TypeDef owner, MethodDef bgEntry)
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
    }
}

