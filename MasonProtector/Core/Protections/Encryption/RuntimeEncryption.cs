using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
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
    internal class RuntimeEncryptionProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal RuntimeEncryptionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyRuntimeEncryption(ModuleDef module, TypeDef modType)
        {
            byte[] masterKey = engine.CryptoRandom(32);
            byte[] masterSalt = engine.CryptoRandom(16);

            var storageType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            storageType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(storageType);
            engine.injectedTypes.Add(storageType);

            var targetMethods = new List<MethodDef>();
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                if (type == storageType) continue;

                if (type.HasGenericParameters) continue;
                if (engine.IsVBInfrastructure(type)) continue;

                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (method.IsConstructor || method.IsStaticConstructor) continue;

                    if (method.HasGenericParameters) continue;
                    if (method.Name == "Create__Instance__" || method.Name == "Dispose__Instance__") continue;
                    if (engine.IsMethodUserExcluded(method)) continue;
                    targetMethods.Add(method);
                }
            }

            if (targetMethods.Count == 0) return;

            foreach (MethodDef method in targetMethods)
            {
                try
                {
                    WrapAndEncryptMethod(module, method, masterKey, masterSalt);
                }
                catch { }
            }

            for (int d = 0; d < rng.Next(3, 8); d++)
            {
                var decoyMethod = new MethodDefUser(engine.MakeName(),
                    MethodSig.CreateStatic(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                decoyMethod.Body = new CilBody();
                var dIl = decoyMethod.Body.Instructions;
                for (int x = 0; x < rng.Next(5, 20); x++)
                    dIl.Add(Instruction.Create(DnOpCodes.Nop));
                dIl.Add(Instruction.Create(DnOpCodes.Ret));
                storageType.Methods.Add(decoyMethod);
                engine.injectedMethods.Add(decoyMethod);
            }
        }

        private void WrapAndEncryptMethod(ModuleDef module, MethodDef method,
            byte[] masterKey, byte[] masterSalt)
        {
            var il = method.Body.Instructions;
            if (il.Count < 2) return;

            bool hasExistingHandlers = method.Body.HasExceptionHandlers;

            bool isVoid = method.ReturnType.ElementType == ElementType.Void;

            int methodSeed;
            unchecked { methodSeed = method.MDToken.ToInt32() ^ BitConverter.ToInt32(masterKey, 0); }
            int xorA = methodSeed ^ BitConverter.ToInt32(masterSalt, 0);
            int xorB = methodSeed ^ BitConverter.ToInt32(masterSalt, 4);
            int xorC = methodSeed ^ BitConverter.ToInt32(masterSalt, 8);

            int encEnd = il.Count;
            for (int i = 0; i < encEnd; i++)
            {
                if (!engine.IsIntLoad(il[i])) continue;
                int origVal = engine.ExtractInt(il[i]);
                if (origVal == int.MinValue) continue;

                int pattern = rng.Next(0, 3);
                switch (pattern)
                {
                    case 0:
                    {
                        int layer1 = origVal ^ xorA;
                        int layer2 = layer1 + xorB;
                        int layer3 = ~layer2;
                        il[i].OpCode = DnOpCodes.Ldc_I4;
                        il[i].Operand = layer3;
                        il.Insert(i + 1, Instruction.Create(DnOpCodes.Not));
                        il.Insert(i + 2, Instruction.Create(DnOpCodes.Ldc_I4, xorB));
                        il.Insert(i + 3, Instruction.Create(DnOpCodes.Sub));
                        il.Insert(i + 4, Instruction.Create(DnOpCodes.Ldc_I4, xorA));
                        il.Insert(i + 5, Instruction.Create(DnOpCodes.Xor));
                        i += 5; encEnd += 5;
                        break;
                    }
                    case 1:
                    {
                        int k = rng.Next(int.MinValue + 1, int.MaxValue);
                        il[i].OpCode = DnOpCodes.Ldc_I4;
                        il[i].Operand = k;
                        il.Insert(i + 1, Instruction.Create(DnOpCodes.Ldc_I4, k ^ origVal));
                        il.Insert(i + 2, Instruction.Create(DnOpCodes.Xor));
                        i += 2; encEnd += 2;
                        break;
                    }
                    default:
                    {
                        int layer1 = origVal ^ xorC;
                        int layer2 = ~layer1;
                        il[i].OpCode = DnOpCodes.Ldc_I4;
                        il[i].Operand = layer2;
                        il.Insert(i + 1, Instruction.Create(DnOpCodes.Not));
                        il.Insert(i + 2, Instruction.Create(DnOpCodes.Ldc_I4, xorC));
                        il.Insert(i + 3, Instruction.Create(DnOpCodes.Xor));
                        i += 3; encEnd += 3;
                        break;
                    }
                }
            }

            if (hasExistingHandlers) return;
            {
                var exceptionTypeRef = module.Import(typeof(Exception)).ToTypeSig().ToTypeDefOrRef();

                Local returnLocal = null;
                Instruction trySuccessTarget;
                Instruction finalRet = Instruction.Create(DnOpCodes.Ret);

                if (isVoid)
                {
                    trySuccessTarget = finalRet;
                }
                else
                {
                    returnLocal = new Local(method.ReturnType);
                    method.Body.Variables.Add(returnLocal);
                    trySuccessTarget = Instruction.Create(DnOpCodes.Ldloc, returnLocal);
                }

                for (int i = 0; i < il.Count; i++)
                {
                    if (il[i].OpCode == DnOpCodes.Ret)
                    {
                        if (!isVoid)
                        {
                            il.Insert(i, Instruction.Create(DnOpCodes.Stloc, returnLocal));
                            i++;
                        }
                        il[i].OpCode = DnOpCodes.Leave;
                        il[i].Operand = trySuccessTarget;
                    }
                }

                var catchRethrow = Instruction.Create(DnOpCodes.Rethrow);
                il.Add(catchRethrow);

                if (!isVoid)
                {
                    il.Add(trySuccessTarget);
                }
                il.Add(finalRet);

                var handlerEnd = isVoid ? finalRet : trySuccessTarget;
                method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                {
                    TryStart     = il[0],
                    TryEnd       = catchRethrow,
                    HandlerStart = catchRethrow,
                    HandlerEnd   = handlerEnd,
                    CatchType    = exceptionTypeRef
                });

                method.Body.InitLocals = true;
            }

        }

        internal void ApplyResourceProtection(ModuleDef module, TypeDef modType)
        {

            var resources = module.Resources.OfType<EmbeddedResource>()
                .Where(r => !engine.injectedResources.Contains(r.Name))
                .ToList();
            if (resources.Count == 0) return;

            byte[] masterKey = engine.CryptoRandom(32);
            byte[] masterIv = engine.CryptoRandom(16);
            byte xorSeed = (byte)rng.Next(1, 255);

            var encryptedNames = new List<string>();
            foreach (var res in resources)
            {
                byte[] raw = res.CreateReader().ReadRemainingBytes();

                byte[] compressed;
                using (var ms = new MemoryStream())
                {
                    using (var ds = new DeflateStream(ms, CompressionMode.Compress, true))
                        ds.Write(raw, 0, raw.Length);
                    compressed = ms.ToArray();
                }

                byte[] aesOut;
                using (var aes = Aes.Create())
                {
                    aes.Key = masterKey;
                    aes.IV = masterIv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    using (var enc = aes.CreateEncryptor())
                        aesOut = enc.TransformFinalBlock(compressed, 0, compressed.Length);
                }

                for (int i = 0; i < aesOut.Length; i++)
                    aesOut[i] ^= (byte)(xorSeed ^ (i & 0xFF));

                module.Resources.Remove(res);
                module.Resources.Add(new EmbeddedResource(res.Name, aesOut, res.Attributes));
                encryptedNames.Add(res.Name);
                engine.injectedResources.Add(res.Name);
            }

            var byteArrSig = new SZArraySig(module.CorLibTypes.Byte);
            var strArrSig = new SZArraySig(module.CorLibTypes.String);

            var keyField = new FieldDefUser(engine.MakeName(),
                new FieldSig(byteArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            modType.Fields.Add(keyField);

            var ivField = new FieldDefUser(engine.MakeName(),
                new FieldSig(byteArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            modType.Fields.Add(ivField);

            var xorField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Byte),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            modType.Fields.Add(xorField);

            var namesField = new FieldDefUser(engine.MakeName(),
                new FieldSig(strArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            modType.Fields.Add(namesField);

            var initMethod = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            initMethod.Body = new CilBody();
            var initIl = initMethod.Body.Instructions;

            EmitLoadByteArray(initIl, module, masterKey);
            initIl.Add(Instruction.Create(DnOpCodes.Stsfld, keyField));

            EmitLoadByteArray(initIl, module, masterIv);
            initIl.Add(Instruction.Create(DnOpCodes.Stsfld, ivField));

            initIl.Add(engine.LoadInt(xorSeed));
            initIl.Add(Instruction.Create(DnOpCodes.Conv_U1));
            initIl.Add(Instruction.Create(DnOpCodes.Stsfld, xorField));

            byte[] blob;
            using (var ms = new System.IO.MemoryStream())
            {
                var bw = new System.IO.BinaryWriter(ms);
                bw.Write((int)encryptedNames.Count);
                foreach (var n in encryptedNames)
                {
                    byte[] u8 = System.Text.Encoding.UTF8.GetBytes(n);
                    bw.Write((int)u8.Length);
                    bw.Write(u8);
                }
                bw.Flush();
                blob = ms.ToArray();
            }

            var encodingUtf8Get = module.Import(typeof(System.Text.Encoding).GetProperty("UTF8").GetGetMethod());
            var encodingGetString = module.Import(typeof(System.Text.Encoding)
                .GetMethod("GetString", new[] { typeof(byte[]), typeof(int), typeof(int) }));
            var bitConvToInt32 = module.Import(typeof(BitConverter)
                .GetMethod("ToInt32", new[] { typeof(byte[]), typeof(int) }));

            Local lBlob = new Local(byteArrSig); initMethod.Body.Variables.Add(lBlob);
            Local lOff  = new Local(module.CorLibTypes.Int32); initMethod.Body.Variables.Add(lOff);
            Local lCnt  = new Local(module.CorLibTypes.Int32); initMethod.Body.Variables.Add(lCnt);
            Local lIdx  = new Local(module.CorLibTypes.Int32); initMethod.Body.Variables.Add(lIdx);
            Local lLen  = new Local(module.CorLibTypes.Int32); initMethod.Body.Variables.Add(lLen);
            initMethod.Body.InitLocals = true;

            EmitLoadByteArray(initIl, module, blob);
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lBlob));

            initIl.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lOff));

            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lBlob));
            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lOff));
            initIl.Add(Instruction.Create(DnOpCodes.Call, bitConvToInt32));
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lCnt));

            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lOff));
            initIl.Add(Instruction.Create(DnOpCodes.Ldc_I4_4));
            initIl.Add(Instruction.Create(DnOpCodes.Add));
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lOff));

            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lCnt));
            initIl.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.String.TypeDefOrRef));
            initIl.Add(Instruction.Create(DnOpCodes.Stsfld, namesField));

            initIl.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lIdx));

            var loopTop = Instruction.Create(DnOpCodes.Ldloc, lIdx);
            var loopEnd = Instruction.Create(DnOpCodes.Ret);
            initIl.Add(loopTop);
            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lCnt));
            initIl.Add(Instruction.Create(DnOpCodes.Bge, loopEnd));

            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lBlob));
            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lOff));
            initIl.Add(Instruction.Create(DnOpCodes.Call, bitConvToInt32));
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lLen));

            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lOff));
            initIl.Add(Instruction.Create(DnOpCodes.Ldc_I4_4));
            initIl.Add(Instruction.Create(DnOpCodes.Add));
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lOff));

            initIl.Add(Instruction.Create(DnOpCodes.Ldsfld, namesField));
            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lIdx));
            initIl.Add(Instruction.Create(DnOpCodes.Call, encodingUtf8Get));
            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lBlob));
            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lOff));
            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lLen));
            initIl.Add(Instruction.Create(DnOpCodes.Callvirt, encodingGetString));
            initIl.Add(Instruction.Create(DnOpCodes.Stelem_Ref));

            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lOff));
            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lLen));
            initIl.Add(Instruction.Create(DnOpCodes.Add));
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lOff));

            initIl.Add(Instruction.Create(DnOpCodes.Ldloc, lIdx));
            initIl.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            initIl.Add(Instruction.Create(DnOpCodes.Add));
            initIl.Add(Instruction.Create(DnOpCodes.Stloc, lIdx));
            initIl.Add(Instruction.Create(DnOpCodes.Br, loopTop));

            initIl.Add(loopEnd);
            modType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);
            engine.InjectCallInCctor(module, modType, initMethod);

            MethodDef helperMethod;
            try
            {
                helperMethod = BuildResourceDecryptor(module, modType,
                    keyField, ivField, xorField, namesField);
            }
            catch
            {
                return;
            }

            try
            {
                RewriteResourceCallsites(module, helperMethod);
            }
            catch { }

            bool hasAnyResourcesFile = false;
            foreach (var n in encryptedNames)
            {
                if (n.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
                {
                    hasAnyResourcesFile = true;
                    break;
                }
            }
            if (hasAnyResourcesFile)
            {
                try
                {
                    MethodDef customRMStrAsmCtor;
                    MethodDef customRMTypeFactory;
                    BuildCustomResourceManager(module, helperMethod,
                        out customRMStrAsmCtor, out customRMTypeFactory);
                    RewriteResourceManagerCtorCalls(module, customRMStrAsmCtor, customRMTypeFactory);
                }
                catch
                {

                }

                try
                {
                    MethodDef customCRMCtor = BuildCustomComponentResourceManager(module, helperMethod);
                    RewriteComponentResourceManagerCtorCalls(module, customCRMCtor);
                }
                catch
                {

                }
            }

            for (int d = 0; d < rng.Next(8, 20); d++)
            {
                byte[] fakeData = engine.CryptoRandom(rng.Next(100, 2000));
                module.Resources.Add(new EmbeddedResource(engine.MakeName() + ".bin", fakeData));
            }
        }

        private void BuildCustomResourceManager(ModuleDef module, MethodDef helperMethod,
            out MethodDef strAsmCtorOut, out MethodDef typeCtorOut)
        {
            var rmTypeRef       = module.Import(typeof(System.Resources.ResourceManager));
            var rsTypeRef       = module.Import(typeof(System.Resources.ResourceSet));
            var cultureTypeRef  = module.Import(typeof(System.Globalization.CultureInfo));
            var streamTypeRef   = module.Import(typeof(System.IO.Stream));
            var assemblyTypeRef = module.Import(typeof(System.Reflection.Assembly));
            var typeTypeRef     = module.Import(typeof(System.Type));
            var exceptionRef    = module.Import(typeof(Exception)).ToTypeSig().ToTypeDefOrRef();

            var stringType = module.CorLibTypes.String;
            var boolType   = module.CorLibTypes.Boolean;
            var voidType   = module.CorLibTypes.Void;

            var baseCtorRef = module.Import(typeof(System.Resources.ResourceManager)
                .GetConstructor(new[] { typeof(string), typeof(System.Reflection.Assembly) }));
            var baseCtorTypeRef = module.Import(typeof(System.Resources.ResourceManager)
                .GetConstructor(new[] { typeof(Type) }));
            var typeFullNameGet = module.Import(typeof(Type).GetProperty("FullName").GetGetMethod());
            var typeAssemblyGet = module.Import(typeof(Type).GetProperty("Assembly").GetGetMethod());
            var baseInternalGetRsRef = module.Import(typeof(System.Resources.ResourceManager)
                .GetMethod("InternalGetResourceSet",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
                    null,
                    new[]
                    {
                        typeof(System.Globalization.CultureInfo),
                        typeof(bool), typeof(bool)
                    },
                    null));
            var rsCtorRef = module.Import(typeof(System.Resources.ResourceSet)
                .GetConstructor(new[] { typeof(System.IO.Stream) }));
            var strConcatRef = module.Import(typeof(string)
                .GetMethod("Concat", new[] { typeof(string), typeof(string) }));

            var customRM = new TypeDefUser("", engine.MakeName(), rmTypeRef);
            customRM.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Class |
                                  DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(customRM);
            engine.injectedTypes.Add(customRM);
            engine.lateStringEncryptionExcludedTypes.Add(customRM);

            var rsField = new FieldDefUser(engine.MakeName(),
                new FieldSig(rsTypeRef.ToTypeSig()),
                DnFieldAttributes.Private);
            customRM.Fields.Add(rsField);

            var ctor = new MethodDefUser(".ctor",
                MethodSig.CreateInstance(voidType, stringType, assemblyTypeRef.ToTypeSig()),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
            ctor.Body = new CilBody();
            ctor.Body.InitLocals = true;
            var streamLocal = new Local(streamTypeRef.ToTypeSig());
            ctor.Body.Variables.Add(streamLocal);

            var cIl = ctor.Body.Instructions;

            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            cIl.Add(Instruction.Create(DnOpCodes.Call, baseCtorRef));

            var finalRet       = Instruction.Create(DnOpCodes.Ret);
            var tryStart       = Instruction.Create(DnOpCodes.Ldarg_2);
            var leaveAfterTry  = Instruction.Create(DnOpCodes.Leave, finalRet);
            var catchStart     = Instruction.Create(DnOpCodes.Pop);
            var leaveAfterCatch= Instruction.Create(DnOpCodes.Leave, finalRet);

            cIl.Add(tryStart);
            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            cIl.Add(Instruction.Create(DnOpCodes.Ldstr, ".resources"));
            cIl.Add(Instruction.Create(DnOpCodes.Call, strConcatRef));
            cIl.Add(Instruction.Create(DnOpCodes.Call, helperMethod));
            cIl.Add(Instruction.Create(DnOpCodes.Stloc, streamLocal));
            cIl.Add(Instruction.Create(DnOpCodes.Ldloc, streamLocal));
            cIl.Add(Instruction.Create(DnOpCodes.Brfalse, leaveAfterTry));
            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            cIl.Add(Instruction.Create(DnOpCodes.Ldloc, streamLocal));
            cIl.Add(Instruction.Create(DnOpCodes.Newobj, rsCtorRef));
            cIl.Add(Instruction.Create(DnOpCodes.Stfld, rsField));
            cIl.Add(leaveAfterTry);
            cIl.Add(catchStart);
            cIl.Add(leaveAfterCatch);
            cIl.Add(finalRet);

            ctor.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart     = tryStart,
                TryEnd       = catchStart,
                HandlerStart = catchStart,
                HandlerEnd   = finalRet,
                CatchType    = exceptionRef
            });

            customRM.Methods.Add(ctor);
            engine.injectedMethods.Add(ctor);

            var overrideMethod = new MethodDefUser("InternalGetResourceSet",
                MethodSig.CreateInstance(rsTypeRef.ToTypeSig(),
                    cultureTypeRef.ToTypeSig(), boolType, boolType),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Family | DnMethodAttributes.HideBySig |
                DnMethodAttributes.Virtual | DnMethodAttributes.ReuseSlot);
            overrideMethod.Body = new CilBody();
            var oIl = overrideMethod.Body.Instructions;

            var callBase = Instruction.Create(DnOpCodes.Ldarg_0);
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            oIl.Add(Instruction.Create(DnOpCodes.Ldfld, rsField));
            oIl.Add(Instruction.Create(DnOpCodes.Brfalse, callBase));
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            oIl.Add(Instruction.Create(DnOpCodes.Ldfld, rsField));
            oIl.Add(Instruction.Create(DnOpCodes.Ret));
            oIl.Add(callBase);
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_3));
            oIl.Add(Instruction.Create(DnOpCodes.Call, baseInternalGetRsRef));
            oIl.Add(Instruction.Create(DnOpCodes.Ret));

            customRM.Methods.Add(overrideMethod);
            engine.injectedMethods.Add(overrideMethod);

            strAsmCtorOut = ctor;
            typeCtorOut = null;
        }

        private void RewriteResourceManagerCtorCalls(ModuleDef module,
            MethodDef strAsmCtor, MethodDef unused)
        {
            var typeRef = module.Import(typeof(System.Type));
            var typeFullNameGet = module.Import(typeof(Type).GetProperty("FullName").GetGetMethod());
            var typeAssemblyGet = module.Import(typeof(Type).GetProperty("Assembly").GetGetMethod());

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (engine.IsMethodUserExcluded(method)) continue;
                    var ins = method.Body.Instructions;

                    for (int i = 0; i < ins.Count; i++)
                    {
                        var instr = ins[i];
                        if (instr.OpCode != DnOpCodes.Newobj) continue;
                        var target = instr.Operand as IMethod;
                        if (target == null) continue;
                        if (target.Name != ".ctor") continue;
                        var decl = target.DeclaringType;
                        if (decl == null) continue;
                        if (decl.FullName != "System.Resources.ResourceManager") continue;
                        var sig = target.MethodSig;
                        if (sig == null) continue;

                        if (sig.Params.Count == 2
                            && sig.Params[0].FullName == "System.String"
                            && sig.Params[1].FullName == "System.Reflection.Assembly")
                        {
                            instr.Operand = strAsmCtor;
                        }
                        else if (sig.Params.Count == 3
                            && sig.Params[0].FullName == "System.String"
                            && sig.Params[1].FullName == "System.Reflection.Assembly"
                            && sig.Params[2].FullName == "System.Type")
                        {
                            ins.Insert(i, Instruction.Create(DnOpCodes.Pop));
                            i++;
                            instr.Operand = strAsmCtor;
                        }
                        else if (sig.Params.Count == 1
                            && sig.Params[0].FullName == "System.Type")
                        {
                            Local tempType = new Local(typeRef.ToTypeSig());
                            method.Body.Variables.Add(tempType);
                            method.Body.InitLocals = true;

                            instr.OpCode = DnOpCodes.Stloc;
                            instr.Operand = tempType;

                            int insertAt = i + 1;
                            ins.Insert(insertAt++, Instruction.Create(DnOpCodes.Ldloc, tempType));
                            ins.Insert(insertAt++, Instruction.Create(DnOpCodes.Callvirt, typeFullNameGet));
                            ins.Insert(insertAt++, Instruction.Create(DnOpCodes.Ldloc, tempType));
                            ins.Insert(insertAt++, Instruction.Create(DnOpCodes.Callvirt, typeAssemblyGet));
                            ins.Insert(insertAt++, Instruction.Create(DnOpCodes.Newobj, strAsmCtor));
                            i = insertAt - 1;
                        }
                    }
                }
            }
        }

        private MethodDef BuildCustomComponentResourceManager(ModuleDef module, MethodDef helperMethod)
        {
            var crmTypeRef      = module.Import(typeof(System.ComponentModel.ComponentResourceManager));
            var rsTypeRef       = module.Import(typeof(System.Resources.ResourceSet));
            var cultureTypeRef  = module.Import(typeof(System.Globalization.CultureInfo));
            var streamTypeRef   = module.Import(typeof(System.IO.Stream));
            var typeTypeRef     = module.Import(typeof(System.Type));
            var exceptionRef    = module.Import(typeof(Exception)).ToTypeSig().ToTypeDefOrRef();

            var boolType = module.CorLibTypes.Boolean;
            var voidType = module.CorLibTypes.Void;

            var baseCtorRef = module.Import(typeof(System.ComponentModel.ComponentResourceManager)
                .GetConstructor(new[] { typeof(Type) }));
            var baseInternalGetRsRef = module.Import(typeof(System.Resources.ResourceManager)
                .GetMethod("InternalGetResourceSet",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
                    null,
                    new[]
                    {
                        typeof(System.Globalization.CultureInfo),
                        typeof(bool), typeof(bool)
                    },
                    null));
            var rsCtorRef = module.Import(typeof(System.Resources.ResourceSet)
                .GetConstructor(new[] { typeof(System.IO.Stream) }));
            var typeFullNameGet = module.Import(typeof(Type).GetProperty("FullName").GetGetMethod());
            var typeAssemblyGet = module.Import(typeof(Type).GetProperty("Assembly").GetGetMethod());
            var strConcatRef = module.Import(typeof(string)
                .GetMethod("Concat", new[] { typeof(string), typeof(string) }));

            var customCRM = new TypeDefUser("", engine.MakeName(), crmTypeRef);
            customCRM.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Class |
                                   DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(customCRM);
            engine.injectedTypes.Add(customCRM);

            var rsField = new FieldDefUser(engine.MakeName(),
                new FieldSig(rsTypeRef.ToTypeSig()),
                DnFieldAttributes.Private);
            customCRM.Fields.Add(rsField);

            var ctor = new MethodDefUser(".ctor",
                MethodSig.CreateInstance(voidType, typeTypeRef.ToTypeSig()),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
            ctor.Body = new CilBody();
            ctor.Body.InitLocals = true;
            var streamLocal = new Local(streamTypeRef.ToTypeSig());
            ctor.Body.Variables.Add(streamLocal);

            var cIl = ctor.Body.Instructions;

            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            cIl.Add(Instruction.Create(DnOpCodes.Call, baseCtorRef));

            var finalRet        = Instruction.Create(DnOpCodes.Ret);
            var tryStart        = Instruction.Create(DnOpCodes.Ldarg_1);
            var leaveAfterTry   = Instruction.Create(DnOpCodes.Leave, finalRet);
            var catchStart      = Instruction.Create(DnOpCodes.Pop);
            var leaveAfterCatch = Instruction.Create(DnOpCodes.Leave, finalRet);

            cIl.Add(tryStart);
            cIl.Add(Instruction.Create(DnOpCodes.Callvirt, typeAssemblyGet));
            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            cIl.Add(Instruction.Create(DnOpCodes.Callvirt, typeFullNameGet));
            cIl.Add(Instruction.Create(DnOpCodes.Ldstr, ".resources"));
            cIl.Add(Instruction.Create(DnOpCodes.Call, strConcatRef));
            cIl.Add(Instruction.Create(DnOpCodes.Call, helperMethod));
            cIl.Add(Instruction.Create(DnOpCodes.Stloc, streamLocal));
            cIl.Add(Instruction.Create(DnOpCodes.Ldloc, streamLocal));
            cIl.Add(Instruction.Create(DnOpCodes.Brfalse, leaveAfterTry));
            cIl.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            cIl.Add(Instruction.Create(DnOpCodes.Ldloc, streamLocal));
            cIl.Add(Instruction.Create(DnOpCodes.Newobj, rsCtorRef));
            cIl.Add(Instruction.Create(DnOpCodes.Stfld, rsField));
            cIl.Add(leaveAfterTry);
            cIl.Add(catchStart);
            cIl.Add(leaveAfterCatch);
            cIl.Add(finalRet);

            ctor.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart     = tryStart,
                TryEnd       = catchStart,
                HandlerStart = catchStart,
                HandlerEnd   = finalRet,
                CatchType    = exceptionRef
            });

            customCRM.Methods.Add(ctor);
            engine.injectedMethods.Add(ctor);

            var overrideMethod = new MethodDefUser("InternalGetResourceSet",
                MethodSig.CreateInstance(rsTypeRef.ToTypeSig(),
                    cultureTypeRef.ToTypeSig(), boolType, boolType),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Family | DnMethodAttributes.HideBySig |
                DnMethodAttributes.Virtual | DnMethodAttributes.ReuseSlot);
            overrideMethod.Body = new CilBody();
            var oIl = overrideMethod.Body.Instructions;

            var callBase = Instruction.Create(DnOpCodes.Ldarg_0);
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            oIl.Add(Instruction.Create(DnOpCodes.Ldfld, rsField));
            oIl.Add(Instruction.Create(DnOpCodes.Brfalse, callBase));
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            oIl.Add(Instruction.Create(DnOpCodes.Ldfld, rsField));
            oIl.Add(Instruction.Create(DnOpCodes.Ret));
            oIl.Add(callBase);
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            oIl.Add(Instruction.Create(DnOpCodes.Ldarg_3));
            oIl.Add(Instruction.Create(DnOpCodes.Call, baseInternalGetRsRef));
            oIl.Add(Instruction.Create(DnOpCodes.Ret));

            customCRM.Methods.Add(overrideMethod);
            engine.injectedMethods.Add(overrideMethod);

            return ctor;
        }

        private void RewriteComponentResourceManagerCtorCalls(ModuleDef module, MethodDef customCRMCtor)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (engine.IsMethodUserExcluded(method)) continue;
                    var ins = method.Body.Instructions;
                    for (int i = 0; i < ins.Count; i++)
                    {
                        var instr = ins[i];
                        if (instr.OpCode != DnOpCodes.Newobj) continue;
                        var target = instr.Operand as IMethod;
                        if (target == null) continue;
                        if (target.Name != ".ctor") continue;
                        var decl = target.DeclaringType;
                        if (decl == null) continue;
                        if (decl.FullName != "System.ComponentModel.ComponentResourceManager") continue;
                        var sig = target.MethodSig;
                        if (sig == null || sig.Params.Count != 1) continue;
                        if (sig.Params[0].FullName != "System.Type") continue;
                        instr.Operand = customCRMCtor;
                    }
                }
            }
        }

        private void EmitLoadByteArray(IList<Instruction> il, ModuleDef module, byte[] data)
        {
            il.Add(engine.LoadInt(data.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            for (int i = 0; i < data.Length; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(engine.LoadInt(i));
                il.Add(engine.LoadInt(data[i]));
                il.Add(Instruction.Create(DnOpCodes.Conv_U1));
                il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
            }
        }

        private MethodDef BuildResourceDecryptor(ModuleDef module, TypeDef modType,
            FieldDef keyField, FieldDef ivField, FieldDef xorField, FieldDef namesField)
        {
            var assemblyType = module.Import(typeof(System.Reflection.Assembly));
            var streamType = module.Import(typeof(System.IO.Stream));
            var memStreamType = module.Import(typeof(System.IO.MemoryStream));
            var deflateType = module.Import(typeof(System.IO.Compression.DeflateStream));
            var aesType = module.Import(typeof(System.Security.Cryptography.Aes));
            var symAlgType = module.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm));
            var cryptoTransformType = module.Import(typeof(System.Security.Cryptography.ICryptoTransform));

            var getManifestRef = module.Import(typeof(System.Reflection.Assembly)
                .GetMethod("GetManifestResourceStream", new[] { typeof(string) }));
            var streamGetLength = module.Import(typeof(System.IO.Stream).GetMethod("get_Length"));
            var streamRead = module.Import(typeof(System.IO.Stream)
                .GetMethod("Read", new[] { typeof(byte[]), typeof(int), typeof(int) }));
            var streamCopyTo = module.Import(typeof(System.IO.Stream)
                .GetMethod("CopyTo", new[] { typeof(System.IO.Stream) }));
            var stringOpEquality = module.Import(typeof(string)
                .GetMethod("op_Equality", new[] { typeof(string), typeof(string) }));
            var aesCreate = module.Import(typeof(System.Security.Cryptography.Aes)
                .GetMethod("Create", Type.EmptyTypes));
            var setMode = module.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm)
                .GetMethod("set_Mode", new[] { typeof(System.Security.Cryptography.CipherMode) }));
            var setPadding = module.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm)
                .GetMethod("set_Padding", new[] { typeof(System.Security.Cryptography.PaddingMode) }));
            var setKey = module.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm)
                .GetMethod("set_Key", new[] { typeof(byte[]) }));
            var setIV = module.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm)
                .GetMethod("set_IV", new[] { typeof(byte[]) }));
            var createDecryptor = module.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm)
                .GetMethod("CreateDecryptor", Type.EmptyTypes));
            var transformFinal = module.Import(typeof(System.Security.Cryptography.ICryptoTransform)
                .GetMethod("TransformFinalBlock", new[] { typeof(byte[]), typeof(int), typeof(int) }));
            var memStreamCtorBytes = module.Import(typeof(System.IO.MemoryStream)
                .GetConstructor(new[] { typeof(byte[]) }));
            var memStreamCtorDefault = module.Import(typeof(System.IO.MemoryStream)
                .GetConstructor(Type.EmptyTypes));
            var memStreamToArray = module.Import(typeof(System.IO.MemoryStream).GetMethod("ToArray"));
            var deflateCtor = module.Import(typeof(System.IO.Compression.DeflateStream)
                .GetConstructor(new[]
                {
                    typeof(System.IO.Stream),
                    typeof(System.IO.Compression.CompressionMode)
                }));

            var helper = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(streamType.ToTypeSig(),
                    assemblyType.ToTypeSig(), module.CorLibTypes.String),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            helper.Body = new CilBody();
            helper.Body.InitLocals = true;
            var v = helper.Body.Variables;

            Local lRaw   = v.Add(new Local(streamType.ToTypeSig()));
            Local lNames = v.Add(new Local(new SZArraySig(module.CorLibTypes.String)));
            Local lI     = v.Add(new Local(module.CorLibTypes.Int32));
            Local lLen   = v.Add(new Local(module.CorLibTypes.Int32));
            Local lBuf   = v.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            Local lXk    = v.Add(new Local(module.CorLibTypes.Int32));
            Local lJ     = v.Add(new Local(module.CorLibTypes.Int32));
            Local lAes   = v.Add(new Local(aesType.ToTypeSig()));
            Local lDec   = v.Add(new Local(cryptoTransformType.ToTypeSig()));
            Local lPlain = v.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            Local lMs    = v.Add(new Local(memStreamType.ToTypeSig()));
            Local lDs    = v.Add(new Local(deflateType.ToTypeSig()));
            Local lOut   = v.Add(new Local(memStreamType.ToTypeSig()));

            var il = helper.Body.Instructions;

            var retNullInst  = Instruction.Create(DnOpCodes.Ldnull);
            var loopHead     = Instruction.Create(DnOpCodes.Ldloc, lI);
            var loopAfter    = Instruction.Create(DnOpCodes.Nop);
            var returnRaw    = Instruction.Create(DnOpCodes.Ldloc, lRaw);
            var xorHead      = Instruction.Create(DnOpCodes.Ldloc, lJ);
            var xorAfter     = Instruction.Create(DnOpCodes.Nop);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getManifestRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lRaw));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lRaw));
            var afterNullCheck = Instruction.Create(DnOpCodes.Ldsfld, namesField);
            il.Add(Instruction.Create(DnOpCodes.Brtrue, afterNullCheck));
            il.Add(retNullInst);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(afterNullCheck);
            il.Add(Instruction.Create(DnOpCodes.Stloc, lNames));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lNames));
            var afterNamesNull = Instruction.Create(DnOpCodes.Ldc_I4_0);
            il.Add(Instruction.Create(DnOpCodes.Brtrue, afterNamesNull));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lRaw));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(afterNamesNull);
            il.Add(Instruction.Create(DnOpCodes.Stloc, lI));

            il.Add(loopHead);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lNames));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Bge, returnRaw));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lNames));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lI));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Call, stringOpEquality));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, loopAfter));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lI));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lI));
            il.Add(Instruction.Create(DnOpCodes.Br, loopHead));

            il.Add(returnRaw);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(loopAfter);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lRaw));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, streamGetLength));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lLen));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lLen));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lBuf));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lRaw));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lBuf));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lLen));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, streamRead));
            il.Add(Instruction.Create(DnOpCodes.Pop));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, xorField));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lXk));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lJ));
            il.Add(xorHead);
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lBuf));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Bge, xorAfter));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lBuf));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lJ));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lBuf));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lJ));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lXk));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lJ));
            il.Add(engine.LoadInt(0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Conv_U1));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lJ));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lJ));
            il.Add(Instruction.Create(DnOpCodes.Br, xorHead));
            il.Add(xorAfter);

            il.Add(Instruction.Create(DnOpCodes.Call, aesCreate));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lAes));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lAes));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, setMode));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lAes));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, setPadding));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lAes));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, keyField));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, setKey));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lAes));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, ivField));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, setIV));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lAes));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, createDecryptor));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lDec));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lDec));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lBuf));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lBuf));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, transformFinal));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lPlain));

            il.Add(Instruction.Create(DnOpCodes.Ldloc, lPlain));
            il.Add(Instruction.Create(DnOpCodes.Newobj, memStreamCtorBytes));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lMs));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lMs));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Newobj, deflateCtor));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lDs));
            il.Add(Instruction.Create(DnOpCodes.Newobj, memStreamCtorDefault));
            il.Add(Instruction.Create(DnOpCodes.Stloc, lOut));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lDs));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lOut));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, streamCopyTo));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, lOut));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, memStreamToArray));
            il.Add(Instruction.Create(DnOpCodes.Newobj, memStreamCtorBytes));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            modType.Methods.Add(helper);
            engine.injectedMethods.Add(helper);
            return helper;
        }

        private void RewriteResourceCallsites(ModuleDef module, MethodDef helperMethod)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsTypeUserExcluded(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (engine.IsMethodUserExcluded(method)) continue;
                    var ins = method.Body.Instructions;
                    for (int i = 0; i < ins.Count; i++)
                    {
                        var instr = ins[i];
                        if (instr.OpCode != DnOpCodes.Callvirt && instr.OpCode != DnOpCodes.Call)
                            continue;
                        var target = instr.Operand as IMethod;
                        if (target == null) continue;
                        if (target.Name != "GetManifestResourceStream") continue;
                        var decl = target.DeclaringType;
                        if (decl == null || decl.FullName != "System.Reflection.Assembly") continue;
                        var sig = target.MethodSig;
                        if (sig == null || sig.Params.Count != 1) continue;
                        if (sig.Params[0].FullName != "System.String") continue;
                        instr.OpCode = DnOpCodes.Call;
                        instr.Operand = helperMethod;
                    }
                }
            }
        }
    }
}

