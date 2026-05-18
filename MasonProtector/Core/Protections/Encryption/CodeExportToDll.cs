using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{

    internal class CodeExportToDllProtection
    {
        private Obfuscation engine;

        private static byte[] _engineKey;
        private static readonly object _keyLock = new object();

        private const int HEADER_LEN = 8;
        private const int KEY_LEN = 32;
        private const int ROTATE_BITS = 3;

        internal CodeExportToDllProtection(Obfuscation eng)
        {
            engine = eng;
            EnsureKey();
        }

        private void EnsureKey()
        {
            if (_engineKey != null) return;
            lock (_keyLock)
            {
                if (_engineKey != null) return;
                _engineKey = engine.CryptoRandom(KEY_LEN);
            }
        }

        private byte[] EncryptBytes(byte[] plain)
        {
            byte[] result = new byte[plain.Length + HEADER_LEN];
            byte[] hdr = engine.CryptoRandom(HEADER_LEN);
            Buffer.BlockCopy(hdr, 0, result, 0, HEADER_LEN);
            int keyLen = _engineKey.Length;
            for (int i = 0; i < plain.Length; i++)
            {
                byte b = plain[i];
                b = (byte)(((b << ROTATE_BITS) | (b >> (8 - ROTATE_BITS))) & 0xFF);
                b ^= _engineKey[i % keyLen];
                result[i + HEADER_LEN] = b;
            }
            return result;
        }

        private byte[] DecryptBytes(byte[] enc)
        {
            if (enc == null || enc.Length <= HEADER_LEN) return null;
            int len = enc.Length - HEADER_LEN;
            byte[] result = new byte[len];
            int keyLen = _engineKey.Length;
            for (int i = 0; i < len; i++)
            {
                byte b = enc[i + HEADER_LEN];
                b ^= _engineKey[i % keyLen];
                b = (byte)(((b >> ROTATE_BITS) | (b << (8 - ROTATE_BITS))) & 0xFF);
                result[i] = b;
            }
            return result;
        }

        private void WriteEncryptedDll(ModuleDef dllMod, string dllPath)
        {

            var writerOpts = new ModuleWriterOptions(dllMod);
            writerOpts.MetadataOptions.Flags = (MetadataFlags)0;
            writerOpts.Logger = DummyLogger.NoThrowInstance;
            dllMod.Write(dllPath, writerOpts);
        }

        private byte[] ReadEncryptedDll(string dllPath)
        {
            return File.ReadAllBytes(dllPath);
        }

        private const string ENCRYPTED_EXT = ".dll";

        private static string GetEncryptedFileName(string dllName)
        {
            return dllName;
        }

        internal int AppendResourcesToExistingDll(ModuleDef exeModule, string outputExePath, string dllName)
        {
            if (exeModule == null) return 0;
            if (string.IsNullOrEmpty(outputExePath)) return 0;
            if (string.IsNullOrEmpty(dllName)) dllName = "MasonCore.dll";
            if (!dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                dllName = dllName + ".dll";

            PromoteMembersToAssembly(exeModule);

            string outputDir = Path.GetDirectoryName(outputExePath);
            string encFileName = GetEncryptedFileName(dllName);
            string dllPath = Path.Combine(outputDir, encFileName);
            if (!File.Exists(dllPath)) return 0;

            byte[] dllBytes;
            try { dllBytes = ReadEncryptedDll(dllPath); }
            catch { return 0; }
            if (dllBytes == null) return 0;

            ModuleDefMD dllMod;
            try { dllMod = ModuleDefMD.Load(dllBytes); }
            catch { return 0; }

            var movedNames = MoveEmbeddedResourcesFromExeToDll(exeModule, dllMod);

            if (movedNames.Count > 0)
            {
                try { WriteEncryptedDll(dllMod, dllPath); }
                catch { return 0; }
            }

            try
            {
                string dllShortName = Path.GetFileNameWithoutExtension(dllName);
                InjectResHookAndRewriteCalls(exeModule, dllShortName);
            }
            catch {  }

            return movedNames.Count;
        }

        private List<string> MoveEmbeddedResourcesFromExeToDll(ModuleDef exeModule, ModuleDef dllMod)
        {
            var moved = new List<string>();
            try
            {
                var existing = new HashSet<string>(StringComparer.Ordinal);
                foreach (var dr in dllMod.Resources)
                {
                    if (dr != null && !string.IsNullOrEmpty(dr.Name))
                        existing.Add(dr.Name);
                }

                var toRemove = new List<Resource>();
                foreach (var res in exeModule.Resources)
                {
                    var er = res as EmbeddedResource;
                    if (er == null) continue;
                    if (string.IsNullOrEmpty(er.Name)) continue;

                    if (existing.Contains(er.Name)) { toRemove.Add(res); moved.Add(er.Name); continue; }

                    byte[] data;
                    try
                    {
                        using (var rdr = er.CreateReader().AsStream())
                        using (var ms = new System.IO.MemoryStream())
                        {
                            rdr.CopyTo(ms);
                            data = ms.ToArray();
                        }
                    }
                    catch { continue; }
                    if (data == null) continue;

                    var copy = new EmbeddedResource(er.Name, data, er.Attributes);
                    dllMod.Resources.Add(copy);
                    existing.Add(er.Name);
                    moved.Add(er.Name);
                    toRemove.Add(res);
                }

                foreach (var r in toRemove)
                {
                    try { exeModule.Resources.Remove(r); } catch {  }
                }
            }
            catch {  }
            return moved;
        }

        private void InjectResHookAndRewriteCalls(ModuleDef exeModule, string dllShortName)
        {
            var imp = new Importer(exeModule);
            var assemblyType = imp.Import(typeof(System.Reflection.Assembly));
            var streamType = imp.Import(typeof(System.IO.Stream));
            var asmLoadBytes = imp.Import(typeof(System.Reflection.Assembly)
                .GetMethod("Load", new Type[] { typeof(byte[]) }));
            var getExec = imp.Import(typeof(System.Reflection.Assembly)
                .GetMethod("GetExecutingAssembly", Type.EmptyTypes));
            var getLoc = imp.Import(typeof(System.Reflection.Assembly)
                .GetMethod("get_Location", Type.EmptyTypes));
            var getDir = imp.Import(typeof(System.IO.Path)
                .GetMethod("GetDirectoryName", new Type[] { typeof(string) }));
            var combine = imp.Import(typeof(System.IO.Path)
                .GetMethod("Combine", new Type[] { typeof(string), typeof(string) }));
            var readAllBytes = imp.Import(typeof(System.IO.File)
                .GetMethod("ReadAllBytes", new Type[] { typeof(string) }));
            var getMrsRef = imp.Import(typeof(System.Reflection.Assembly)
                .GetMethod("GetManifestResourceStream", new Type[] { typeof(string) }));
            var getCurrentDomain = imp.Import(typeof(System.AppDomain)
                .GetMethod("get_CurrentDomain", Type.EmptyTypes));
            var addResolve = imp.Import(typeof(System.AppDomain)
                .GetEvent("AssemblyResolve").GetAddMethod());
            var resolveHandlerCtor = imp.Import(typeof(System.ResolveEventHandler)
                .GetConstructor(new Type[] { typeof(object), typeof(IntPtr) }));
            var resolveArgsType = imp.Import(typeof(System.ResolveEventArgs));
            var getArgsName = imp.Import(typeof(System.ResolveEventArgs)
                .GetMethod("get_Name", Type.EmptyTypes));
            var asmNameCtor = imp.Import(typeof(System.Reflection.AssemblyName)
                .GetConstructor(new Type[] { typeof(string) }));
            var getAsmShortName = imp.Import(typeof(System.Reflection.AssemblyName)
                .GetMethod("get_Name", Type.EmptyTypes));
            var stringEq = imp.Import(typeof(string)
                .GetMethod("op_Equality", new Type[] { typeof(string), typeof(string) }));

            var hookType = new TypeDefUser("", engine.MakeName(),
                exeModule.CorLibTypes.Object.TypeDefOrRef);
            hookType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            exeModule.Types.Add(hookType);
            engine.injectedTypes.Add(hookType);

            var byteArrSig = new dnlib.DotNet.SZArraySig(exeModule.CorLibTypes.Byte);

            var dllField = new FieldDefUser(engine.MakeName(),
                new FieldSig(assemblyType.ToTypeSig()),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            hookType.Fields.Add(dllField);

            var keyField = new FieldDefUser(engine.MakeName(),
                new FieldSig(byteArrSig),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            hookType.Fields.Add(keyField);

            var hookSig = MethodSig.CreateStatic(streamType.ToTypeSig(),
                assemblyType.ToTypeSig(), exeModule.CorLibTypes.String);
            var hook = new MethodDefUser(engine.MakeName(), hookSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            hookType.Methods.Add(hook);
            engine.injectedMethods.Add(hook);

            hook.Body = new CilBody();
            hook.Body.InitLocals = true;
            hook.Body.Variables.Add(new Local(streamType.ToTypeSig()));
            var il = hook.Body.Instructions;

            Instruction haveDll       = Instruction.Create(DnOpCodes.Ldsfld, dllField);
            Instruction tryFromDll    = Instruction.Create(DnOpCodes.Ldsfld, dllField);
            Instruction returnDllStm  = Instruction.Create(DnOpCodes.Ldloc_0);
            Instruction fallbackAsm   = Instruction.Create(DnOpCodes.Ldarg_0);
            Instruction returnNull    = Instruction.Create(DnOpCodes.Ldnull);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, dllField));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, haveDll));

            var asmLoadFromImp = new Importer(exeModule).Import(typeof(System.Reflection.Assembly)
                .GetMethod("LoadFrom", new Type[] { typeof(string) }));
            il.Add(Instruction.Create(DnOpCodes.Call, getExec));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getLoc));
            il.Add(Instruction.Create(DnOpCodes.Call, getDir));
            il.Add(Instruction.Create(DnOpCodes.Ldstr, dllShortName + ENCRYPTED_EXT));
            il.Add(Instruction.Create(DnOpCodes.Call, combine));
            il.Add(Instruction.Create(DnOpCodes.Call, asmLoadFromImp));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, dllField));

            il.Add(haveDll);
            il.Add(Instruction.Create(DnOpCodes.Brfalse, fallbackAsm));

            il.Add(tryFromDll);
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getMrsRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, fallbackAsm));
            il.Add(returnDllStm);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(fallbackAsm);
            il.Add(Instruction.Create(DnOpCodes.Brfalse, returnNull));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getMrsRef));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(returnNull);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            RewriteResourceCallsites(exeModule, hook, hookType);

            InstallResourceResolveHandlerOnly(exeModule, hookType, dllField, dllShortName);
        }

        private void InstallResourceResolveHandlerOnly(ModuleDef exeModule, TypeDef hookType,
            FieldDef dllField, string dllShortName)
        {
            try
            {
                var imp = new Importer(exeModule);
                var assemblyType = imp.Import(typeof(System.Reflection.Assembly));
                var resolveArgsType = imp.Import(typeof(System.ResolveEventArgs));
                var getExec = imp.Import(typeof(System.Reflection.Assembly)
                    .GetMethod("GetExecutingAssembly", Type.EmptyTypes));
                var getLoc = imp.Import(typeof(System.Reflection.Assembly)
                    .GetMethod("get_Location", Type.EmptyTypes));
                var getDir = imp.Import(typeof(System.IO.Path)
                    .GetMethod("GetDirectoryName", new Type[] { typeof(string) }));
                var combine = imp.Import(typeof(System.IO.Path)
                    .GetMethod("Combine", new Type[] { typeof(string), typeof(string) }));
                var asmLoadFrom = imp.Import(typeof(System.Reflection.Assembly)
                    .GetMethod("LoadFrom", new Type[] { typeof(string) }));
                var getCurrentDomain = imp.Import(typeof(System.AppDomain)
                    .GetMethod("get_CurrentDomain", Type.EmptyTypes));
                var addResResolve = imp.Import(typeof(System.AppDomain)
                    .GetEvent("ResourceResolve").GetAddMethod());
                var resolveHandlerCtor = imp.Import(typeof(System.ResolveEventHandler)
                    .GetConstructor(new Type[] { typeof(object), typeof(IntPtr) }));

                var handlerSig = MethodSig.CreateStatic(assemblyType.ToTypeSig(),
                    exeModule.CorLibTypes.Object, resolveArgsType.ToTypeSig());
                var handler = new MethodDefUser(engine.MakeName(), handlerSig,
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                hookType.Methods.Add(handler);
                engine.injectedMethods.Add(handler);

                handler.Body = new CilBody();
                var hil = handler.Body.Instructions;
                Instruction retDll = Instruction.Create(DnOpCodes.Ldsfld, dllField);
                Instruction tryStart = Instruction.Create(DnOpCodes.Ldsfld, dllField);
                Instruction catchStart = Instruction.Create(DnOpCodes.Pop);
                Instruction leaveOk = Instruction.Create(DnOpCodes.Leave, retDll);
                Instruction leaveCatch = Instruction.Create(DnOpCodes.Leave, retDll);

                hil.Add(tryStart);
                hil.Add(Instruction.Create(DnOpCodes.Brtrue, leaveOk));
                hil.Add(Instruction.Create(DnOpCodes.Call, getExec));
                hil.Add(Instruction.Create(DnOpCodes.Callvirt, getLoc));
                hil.Add(Instruction.Create(DnOpCodes.Call, getDir));
                hil.Add(Instruction.Create(DnOpCodes.Ldstr, dllShortName + ENCRYPTED_EXT));
                hil.Add(Instruction.Create(DnOpCodes.Call, combine));
                hil.Add(Instruction.Create(DnOpCodes.Call, asmLoadFrom));
                hil.Add(Instruction.Create(DnOpCodes.Stsfld, dllField));
                hil.Add(leaveOk);
                hil.Add(catchStart);
                hil.Add(leaveCatch);
                hil.Add(retDll);
                hil.Add(Instruction.Create(DnOpCodes.Ret));

                var ex = new ExceptionHandler(ExceptionHandlerType.Catch);
                ex.TryStart = tryStart;
                ex.TryEnd = catchStart;
                ex.HandlerStart = catchStart;
                ex.HandlerEnd = retDll;
                ex.CatchType = exeModule.CorLibTypes.Object.TypeDefOrRef;
                handler.Body.ExceptionHandlers.Add(ex);

                var registerSig = MethodSig.CreateStatic(exeModule.CorLibTypes.Void);
                var register = new MethodDefUser(engine.MakeName(), registerSig,
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                hookType.Methods.Add(register);
                engine.injectedMethods.Add(register);

                register.Body = new CilBody();
                var ril = register.Body.Instructions;
                Instruction regEnd = Instruction.Create(DnOpCodes.Ret);
                Instruction regTryStart = Instruction.Create(DnOpCodes.Call, getCurrentDomain);
                Instruction regCatchStart = Instruction.Create(DnOpCodes.Pop);
                ril.Add(regTryStart);
                ril.Add(Instruction.Create(DnOpCodes.Ldnull));
                ril.Add(Instruction.Create(DnOpCodes.Ldftn, handler));
                ril.Add(Instruction.Create(DnOpCodes.Newobj, resolveHandlerCtor));
                ril.Add(Instruction.Create(DnOpCodes.Callvirt, addResResolve));
                ril.Add(Instruction.Create(DnOpCodes.Leave, regEnd));
                ril.Add(regCatchStart);
                ril.Add(Instruction.Create(DnOpCodes.Leave, regEnd));
                ril.Add(regEnd);

                var regEx = new ExceptionHandler(ExceptionHandlerType.Catch);
                regEx.TryStart = regTryStart;
                regEx.TryEnd = regCatchStart;
                regEx.HandlerStart = regCatchStart;
                regEx.HandlerEnd = regEnd;
                regEx.CatchType = exeModule.CorLibTypes.Object.TypeDefOrRef;
                register.Body.ExceptionHandlers.Add(regEx);

                var moduleType = exeModule.GlobalType;
                if (moduleType == null) return;
                MethodDef cctor = moduleType.FindStaticConstructor();
                if (cctor == null)
                {
                    cctor = new MethodDefUser(".cctor",
                        MethodSig.CreateStatic(exeModule.CorLibTypes.Void),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Private | DnMethodAttributes.Static |
                        DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                        DnMethodAttributes.RTSpecialName);
                    cctor.Body = new CilBody();
                    cctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                    moduleType.Methods.Add(cctor);
                    engine.injectedMethods.Add(cctor);
                }
                if (cctor.Body == null) cctor.Body = new CilBody();
                if (cctor.Body.Instructions.Count == 0)
                    cctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                cctor.Body.Instructions.Insert(0, Instruction.Create(DnOpCodes.Call, register));
            }
            catch {  }
        }

        private void InstallEncryptedLoaderAndResolvers(ModuleDef exeModule, TypeDef hookType,
            FieldDef dllField, FieldDef keyField,
            MethodDef keyInitMethod, MethodDef decryptMethod, string dllShortName,
            IMethod readAllBytes, IMethod asmLoadBytes,
            IMethod getExec, IMethod getLoc, IMethod getDir, IMethod combine,
            IMethod getCurrentDomain, IMethod resolveHandlerCtor,
            IMethod getArgsName, IMethod asmNameCtor, IMethod getAsmShortName, IMethod stringEq)
        {
            try
            {
                var imp = new Importer(exeModule);
                var assemblyType = imp.Import(typeof(System.Reflection.Assembly));
                var resolveArgsType = imp.Import(typeof(System.ResolveEventArgs));
                var addAsmResolve = imp.Import(typeof(System.AppDomain)
                    .GetEvent("AssemblyResolve").GetAddMethod());
                var addResResolve = imp.Import(typeof(System.AppDomain)
                    .GetEvent("ResourceResolve").GetAddMethod());

                var loadDllSig = MethodSig.CreateStatic(assemblyType.ToTypeSig());
                var loadDll = new MethodDefUser(engine.MakeName(), loadDllSig,
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                hookType.Methods.Add(loadDll);
                engine.injectedMethods.Add(loadDll);

                loadDll.Body = new CilBody();
                var lil = loadDll.Body.Instructions;
                Instruction loadEnd = Instruction.Create(DnOpCodes.Ldsfld, dllField);
                Instruction loadCatchStart = Instruction.Create(DnOpCodes.Pop);
                Instruction loadTryStart = Instruction.Create(DnOpCodes.Ldsfld, dllField);
                Instruction loadLeaveOk = Instruction.Create(DnOpCodes.Leave, loadEnd);
                Instruction loadLeaveCatch = Instruction.Create(DnOpCodes.Leave, loadEnd);

                lil.Add(loadTryStart);
                lil.Add(Instruction.Create(DnOpCodes.Brtrue, loadLeaveOk));
                lil.Add(Instruction.Create(DnOpCodes.Call, getExec));
                lil.Add(Instruction.Create(DnOpCodes.Callvirt, getLoc));
                lil.Add(Instruction.Create(DnOpCodes.Call, getDir));
                lil.Add(Instruction.Create(DnOpCodes.Ldstr, dllShortName + ENCRYPTED_EXT));
                lil.Add(Instruction.Create(DnOpCodes.Call, combine));
                lil.Add(Instruction.Create(DnOpCodes.Call, readAllBytes));
                lil.Add(Instruction.Create(DnOpCodes.Call, decryptMethod));
                lil.Add(Instruction.Create(DnOpCodes.Call, asmLoadBytes));
                lil.Add(Instruction.Create(DnOpCodes.Stsfld, dllField));
                lil.Add(loadLeaveOk);
                lil.Add(loadCatchStart);
                lil.Add(loadLeaveCatch);
                lil.Add(loadEnd);
                lil.Add(Instruction.Create(DnOpCodes.Ret));

                var loadEx = new ExceptionHandler(ExceptionHandlerType.Catch);
                loadEx.TryStart = loadTryStart;
                loadEx.TryEnd = loadCatchStart;
                loadEx.HandlerStart = loadCatchStart;
                loadEx.HandlerEnd = loadEnd;
                loadEx.CatchType = exeModule.CorLibTypes.Object.TypeDefOrRef;
                loadDll.Body.ExceptionHandlers.Add(loadEx);

                var asmHandlerSig = MethodSig.CreateStatic(assemblyType.ToTypeSig(),
                    exeModule.CorLibTypes.Object, resolveArgsType.ToTypeSig());
                var asmHandler = new MethodDefUser(engine.MakeName(), asmHandlerSig,
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                hookType.Methods.Add(asmHandler);
                engine.injectedMethods.Add(asmHandler);

                asmHandler.Body = new CilBody();
                asmHandler.Body.InitLocals = true;
                asmHandler.Body.Variables.Add(new Local(exeModule.CorLibTypes.String));
                var ail = asmHandler.Body.Instructions;

                ail.Add(Instruction.Create(DnOpCodes.Ldarg_1));
                ail.Add(Instruction.Create(DnOpCodes.Callvirt, getArgsName));
                ail.Add(Instruction.Create(DnOpCodes.Newobj, asmNameCtor));
                ail.Add(Instruction.Create(DnOpCodes.Callvirt, getAsmShortName));
                ail.Add(Instruction.Create(DnOpCodes.Stloc_0));
                Instruction nullEnd = Instruction.Create(DnOpCodes.Ldnull);
                ail.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                ail.Add(Instruction.Create(DnOpCodes.Ldstr, dllShortName));
                ail.Add(Instruction.Create(DnOpCodes.Call, stringEq));
                ail.Add(Instruction.Create(DnOpCodes.Brfalse, nullEnd));
                ail.Add(Instruction.Create(DnOpCodes.Call, loadDll));
                ail.Add(Instruction.Create(DnOpCodes.Ret));
                ail.Add(nullEnd);
                ail.Add(Instruction.Create(DnOpCodes.Ret));

                var resHandlerSig = MethodSig.CreateStatic(assemblyType.ToTypeSig(),
                    exeModule.CorLibTypes.Object, resolveArgsType.ToTypeSig());
                var resHandler = new MethodDefUser(engine.MakeName(), resHandlerSig,
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                hookType.Methods.Add(resHandler);
                engine.injectedMethods.Add(resHandler);

                resHandler.Body = new CilBody();
                var rsil = resHandler.Body.Instructions;
                rsil.Add(Instruction.Create(DnOpCodes.Call, loadDll));
                rsil.Add(Instruction.Create(DnOpCodes.Ret));

                var registerSig = MethodSig.CreateStatic(exeModule.CorLibTypes.Void);
                var register = new MethodDefUser(engine.MakeName(), registerSig,
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                hookType.Methods.Add(register);
                engine.injectedMethods.Add(register);

                register.Body = new CilBody();
                var ril = register.Body.Instructions;

                ril.Add(Instruction.Create(DnOpCodes.Call, getCurrentDomain));
                ril.Add(Instruction.Create(DnOpCodes.Ldnull));
                ril.Add(Instruction.Create(DnOpCodes.Ldftn, asmHandler));
                ril.Add(Instruction.Create(DnOpCodes.Newobj, resolveHandlerCtor));
                ril.Add(Instruction.Create(DnOpCodes.Callvirt, addAsmResolve));
                ril.Add(Instruction.Create(DnOpCodes.Call, getCurrentDomain));
                ril.Add(Instruction.Create(DnOpCodes.Ldnull));
                ril.Add(Instruction.Create(DnOpCodes.Ldftn, resHandler));
                ril.Add(Instruction.Create(DnOpCodes.Newobj, resolveHandlerCtor));
                ril.Add(Instruction.Create(DnOpCodes.Callvirt, addResResolve));
                ril.Add(Instruction.Create(DnOpCodes.Call, keyInitMethod));
                ril.Add(Instruction.Create(DnOpCodes.Ret));

                var entry = exeModule.EntryPoint;
                if (entry == null || entry.Body == null) return;
                if (entry.Body.Instructions.Count == 0)
                    entry.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                entry.Body.Instructions.Insert(0, Instruction.Create(DnOpCodes.Call, register));
            }
            catch {  }
        }

        private MethodDef BuildKeyInitializer(ModuleDef exeModule, TypeDef hookType, FieldDef keyField, byte[] key)
        {
            var byteArrSig = new dnlib.DotNet.SZArraySig(exeModule.CorLibTypes.Byte);
            var sig = MethodSig.CreateStatic(exeModule.CorLibTypes.Void);
            var m = new MethodDefUser(engine.MakeName(), sig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            var il = m.Body.Instructions;

            byte mask = (byte)(engine.rng.Next(1, 255));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, key.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, exeModule.CorLibTypes.Byte.TypeDefOrRef));

            for (int i = 0; i < key.Length; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Dup));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, i));
                int xored = key[i] ^ mask;
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, xored));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)mask));
                il.Add(Instruction.Create(DnOpCodes.Xor));
                il.Add(Instruction.Create(DnOpCodes.Conv_U1));
                il.Add(Instruction.Create(DnOpCodes.Stelem_I1));
            }

            il.Add(Instruction.Create(DnOpCodes.Stsfld, keyField));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            hookType.Methods.Add(m);
            return m;
        }

        private MethodDef BuildDecryptMethod(ModuleDef exeModule, TypeDef hookType, FieldDef keyField)
        {
            var byteArrSig = new dnlib.DotNet.SZArraySig(exeModule.CorLibTypes.Byte);
            var sig = MethodSig.CreateStatic(byteArrSig, byteArrSig);
            var m = new MethodDefUser(engine.MakeName(), sig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            m.Body.InitLocals = true;

            m.Body.Variables.Add(new Local(byteArrSig));
            m.Body.Variables.Add(new Local(exeModule.CorLibTypes.Int32));
            m.Body.Variables.Add(new Local(exeModule.CorLibTypes.Int32));
            m.Body.Variables.Add(new Local(exeModule.CorLibTypes.Int32));
            m.Body.Variables.Add(new Local(exeModule.CorLibTypes.Int32));

            var il = m.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, HEADER_LEN));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, keyField));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Newarr, exeModule.CorLibTypes.Byte.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            var loopCond = Instruction.Create(DnOpCodes.Ldloc_2);
            il.Add(Instruction.Create(DnOpCodes.Br, loopCond));

            var loopBody = Instruction.Create(DnOpCodes.Ldarg_0);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, HEADER_LEN));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, keyField));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Rem));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));

            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, m.Body.Variables[4]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, m.Body.Variables[4]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, ROTATE_BITS));
            il.Add(Instruction.Create(DnOpCodes.Shr_Un));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, m.Body.Variables[4]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 8 - ROTATE_BITS));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Conv_U1));

            il.Add(Instruction.Create(DnOpCodes.Stelem_I1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(loopCond);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            hookType.Methods.Add(m);
            return m;
        }

        private MethodDef BuildLoadDllMethod(ModuleDef exeModule, TypeDef hookType, FieldDef dllField,
            MethodDef decryptMethod, IMethod getExec, IMethod getLoc, IMethod getDir, IMethod combine,
            IMethod readAllBytes, IMethod asmLoadBytes, string dllShortName)
        {
            var imp = new Importer(exeModule);
            var assemblyType = imp.Import(typeof(System.Reflection.Assembly)).ToTypeSig();
            var sig = MethodSig.CreateStatic(assemblyType);
            var m = new MethodDefUser(engine.MakeName(), sig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            m.Body.InitLocals = true;
            var il = m.Body.Instructions;

            Instruction tryReturnExisting = Instruction.Create(DnOpCodes.Ldsfld, dllField);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, dllField));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, tryReturnExisting));

            il.Add(Instruction.Create(DnOpCodes.Call, getExec));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getLoc));
            il.Add(Instruction.Create(DnOpCodes.Call, getDir));
            il.Add(Instruction.Create(DnOpCodes.Ldstr, dllShortName + ".dll"));
            il.Add(Instruction.Create(DnOpCodes.Call, combine));

            var asmLoadFromImp = new Importer(exeModule).Import(typeof(System.Reflection.Assembly)
                .GetMethod("LoadFrom", new Type[] { typeof(string) }));
            il.Add(Instruction.Create(DnOpCodes.Call, asmLoadFromImp));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, dllField));

            il.Add(tryReturnExisting);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            hookType.Methods.Add(m);
            return m;
        }

        private MethodDef BuildAssemblyResolveHandler(ModuleDef exeModule, TypeDef hookType,
            FieldDef dllField, MethodDef loadDllMethod, IMethod getArgsName, IMethod asmNameCtor,
            IMethod getAsmShortName, IMethod stringEq, string dllShortName)
        {
            var imp = new Importer(exeModule);
            var assemblyType = imp.Import(typeof(System.Reflection.Assembly)).ToTypeSig();
            var resolveArgsType = imp.Import(typeof(System.ResolveEventArgs)).ToTypeSig();

            var sig = MethodSig.CreateStatic(assemblyType,
                exeModule.CorLibTypes.Object, resolveArgsType);
            var m = new MethodDefUser(engine.MakeName(), sig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            m.Body.InitLocals = true;
            m.Body.Variables.Add(new Local(exeModule.CorLibTypes.String));
            var il = m.Body.Instructions;

            Instruction tryLoad = Instruction.Create(DnOpCodes.Call, loadDllMethod);
            Instruction returnNull = Instruction.Create(DnOpCodes.Ldnull);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getArgsName));
            il.Add(Instruction.Create(DnOpCodes.Newobj, asmNameCtor));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getAsmShortName));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldstr, dllShortName));
            il.Add(Instruction.Create(DnOpCodes.Call, stringEq));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, returnNull));

            il.Add(tryLoad);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(returnNull);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            hookType.Methods.Add(m);
            return m;
        }

        private void EnsureHookTypeCctorWithResolve(ModuleDef exeModule, TypeDef hookType,
            MethodDef keyInit, MethodDef loadDllMethod, MethodDef resolveHandler,
            IMethod getCurrentDomain, IMethod addResolve, IMethod resolveHandlerCtor)
        {
            var cctorSig = MethodSig.CreateStatic(exeModule.CorLibTypes.Void);
            var cctor = new MethodDefUser(".cctor", cctorSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig |
                DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
            cctor.Body = new CilBody();
            var il = cctor.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Call, keyInit));

            il.Add(Instruction.Create(DnOpCodes.Call, getCurrentDomain));
            il.Add(Instruction.Create(DnOpCodes.Ldnull));
            il.Add(Instruction.Create(DnOpCodes.Ldftn, resolveHandler));
            il.Add(Instruction.Create(DnOpCodes.Newobj, resolveHandlerCtor));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, addResolve));

            il.Add(Instruction.Create(DnOpCodes.Call, loadDllMethod));
            il.Add(Instruction.Create(DnOpCodes.Pop));

            il.Add(Instruction.Create(DnOpCodes.Ret));
            hookType.Methods.Add(cctor);
        }

        private void InjectHookTouchInModuleCctor(ModuleDef exeModule, TypeDef hookType, FieldDef anyField)
        {
            var modType = exeModule.GlobalType;
            if (modType != null)
            {
                var cctor = modType.FindStaticConstructor();
                if (cctor == null)
                {
                    var cctorSig = MethodSig.CreateStatic(exeModule.CorLibTypes.Void);
                    cctor = new MethodDefUser(".cctor", cctorSig,
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig |
                        DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
                    cctor.Body = new CilBody();
                    cctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                    modType.Methods.Add(cctor);
                }

                var insts = cctor.Body.Instructions;
                insts.Insert(0, Instruction.Create(DnOpCodes.Pop));
                insts.Insert(0, Instruction.Create(DnOpCodes.Ldsfld, anyField));
            }

            WrapEntryPoint(exeModule, hookType, anyField);
        }

        private void WrapEntryPoint(ModuleDef exeModule, TypeDef hookType, FieldDef anyField)
        {
            var origEntry = exeModule.EntryPoint;
            if (origEntry == null) return;
            var origSig = origEntry.MethodSig;
            if (origSig == null) return;

            var newParams = new List<TypeSig>();
            for (int i = 0; i < origSig.Params.Count; i++)
                newParams.Add(origSig.Params[i]);
            var wrapperSig = MethodSig.CreateStatic(origSig.RetType, newParams.ToArray());

            var wrapper = new MethodDefUser(engine.MakeName(), wrapperSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            foreach (var ca in origEntry.CustomAttributes)
                wrapper.CustomAttributes.Add(ca);

            wrapper.Body = new CilBody();
            wrapper.Body.InitLocals = true;
            var il = wrapper.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, anyField));
            il.Add(Instruction.Create(DnOpCodes.Pop));

            for (int i = 0; i < wrapper.Parameters.Count; i++)
                il.Add(Instruction.Create(DnOpCodes.Ldarg, wrapper.Parameters[i]));

            il.Add(Instruction.Create(DnOpCodes.Call, origEntry));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            hookType.Methods.Add(wrapper);
            engine.injectedMethods.Add(wrapper);
            exeModule.EntryPoint = wrapper;
        }

        private void RewriteResourceCallsites(ModuleDef exeModule, MethodDef hook, TypeDef hookType)
        {
            string targetName = "GetManifestResourceStream";
            string targetDecl = "System.Reflection.Assembly";

            foreach (TypeDef t in exeModule.GetTypes())
            {
                if (t == hookType) continue;
                foreach (var m in t.Methods)
                {
                    if (m == null || m.Body == null || !m.Body.HasInstructions) continue;
                    var il = m.Body.Instructions;
                    for (int i = 0; i < il.Count; i++)
                    {
                        var inst = il[i];
                        if (inst.OpCode != DnOpCodes.Callvirt && inst.OpCode != DnOpCodes.Call) continue;
                        var mr = inst.Operand as IMethod;
                        if (mr == null) continue;
                        if (mr.Name != targetName) continue;
                        var declType = mr.DeclaringType;
                        if (declType == null || declType.FullName != targetDecl) continue;
                        var sig = mr.MethodSig;
                        if (sig == null) continue;
                        if (sig.Params.Count != 1) continue;
                        if (sig.Params[0].FullName != "System.String") continue;

                        inst.OpCode = DnOpCodes.Call;
                        inst.Operand = hook;
                    }
                }
            }
        }

        internal int ApplyPostSave(string outputExePath, string dllName)
        {
            if (string.IsNullOrEmpty(outputExePath) || !File.Exists(outputExePath)) return 0;
            if (string.IsNullOrEmpty(dllName)) dllName = "MasonCore.dll";
            if (!dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                dllName = dllName + ".dll";

            byte[] exeBytes;
            try { exeBytes = File.ReadAllBytes(outputExePath); }
            catch { return 0; }

            ModuleDefMD exeModule;
            try { exeModule = ModuleDefMD.Load(exeBytes); }
            catch { return 0; }

            int moved = Apply(exeModule, outputExePath, dllName);
            if (moved == 0) return 0;

            try
            {
                var ww = new ModuleWriterOptions(exeModule);
                ww.MetadataOptions.Flags = (MetadataFlags)0;
                ww.Logger = DummyLogger.NoThrowInstance;
                exeModule.Write(outputExePath, ww);
            }
            catch
            {
                return 0;
            }

            return moved;
        }

        internal int Apply(ModuleDef exeModule, string outputExePath, string dllName)
        {
            if (exeModule == null) return 0;
            if (string.IsNullOrEmpty(outputExePath)) return 0;
            if (string.IsNullOrEmpty(dllName)) dllName = "MasonCore.dll";
            if (!dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                dllName = dllName + ".dll";

            string outputDir = Path.GetDirectoryName(outputExePath);
            string encFileName = GetEncryptedFileName(dllName);
            string dllPath = Path.Combine(outputDir, encFileName);
            string dllShortName = Path.GetFileNameWithoutExtension(dllName);

            var dllAsm = new AssemblyDefUser(dllShortName, new Version(1, 0, 0, 0));
            dllAsm.HashAlgorithm = AssemblyHashAlgorithm.SHA1;
            var corlibRef = exeModule.CorLibTypes.AssemblyRef;
            var dllMod = new ModuleDefUser(dllName, Guid.NewGuid(), corlibRef);
            dllMod.Kind = ModuleKind.Dll;
            dllMod.RuntimeVersion = exeModule.RuntimeVersion;
            dllAsm.Modules.Add(dllMod);

            int holderCount = 10 + engine.rng.Next(9);
            var holderTypes = new List<TypeDef>(holderCount);
            for (int hi = 0; hi < holderCount; hi++)
            {
                var ht = new TypeDefUser("", engine.MakeName(),
                    dllMod.CorLibTypes.Object.TypeDefOrRef);
                ht.Attributes = DnTypeAttributes.Public | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                dllMod.Types.Add(ht);
                holderTypes.Add(ht);
            }

            PromoteMembersToAssembly(exeModule);

            AddInternalsVisibleTo(exeModule, dllShortName);

            int resCopied = CopyEmbeddedResourcesToDll(exeModule, dllMod);

            int relocated = 0;
            var candidates = new List<MethodDef>();

            foreach (var sub in engine.designerSplitSubMethods)
            {
                if (CanRelocate(sub)) candidates.Add(sub);
            }

            var seen = new HashSet<MethodDef>(candidates);
            foreach (TypeDef type in exeModule.GetTypes())
            {
                if (type == null) continue;
                if (type.Name == "<Module>" || type.IsGlobalModuleType) continue;
                if (engine.IsCompilerGenerated(type)) continue;
                if (engine.injectedTypes.Contains(type)) continue;
                if (engine.IsTypeUserExcluded(type)) continue;

                foreach (var m in type.Methods)
                {
                    if (m == null) continue;
                    if (seen.Contains(m)) continue;
                    if (engine.injectedMethods.Contains(m)) continue;
                    if (!CanRelocate(m)) continue;
                    if (m == exeModule.EntryPoint) continue;
                    candidates.Add(m);
                    seen.Add(m);
                }
            }

            foreach (var sub in candidates)
            {
                try
                {

                    var holderType = holderTypes[engine.rng.Next(holderTypes.Count)];
                    if (RelocateMethodToDll(sub, holderType, dllMod, exeModule))
                        relocated++;
                }
                catch {  }
            }

            if (relocated == 0 && resCopied == 0)
            {
                return 0;
            }

            try
            {
                WriteEncryptedDll(dllMod, dllPath);
            }
            catch
            {
                return 0;
            }

            return relocated + resCopied;
        }

        private int CopyEmbeddedResourcesToDll(ModuleDef exeModule, ModuleDef dllMod)
        {
            int count = 0;
            try
            {
                var existing = new HashSet<string>(StringComparer.Ordinal);
                foreach (var dr in dllMod.Resources)
                {
                    if (dr != null && !string.IsNullOrEmpty(dr.Name))
                        existing.Add(dr.Name);
                }

                foreach (var res in exeModule.Resources)
                {
                    var er = res as EmbeddedResource;
                    if (er == null) continue;
                    if (string.IsNullOrEmpty(er.Name)) continue;
                    if (existing.Contains(er.Name)) continue;

                    byte[] data;
                    try
                    {
                        using (var rdr = er.CreateReader().AsStream())
                        using (var ms = new System.IO.MemoryStream())
                        {
                            rdr.CopyTo(ms);
                            data = ms.ToArray();
                        }
                    }
                    catch { continue; }
                    if (data == null) continue;

                    var copy = new EmbeddedResource(er.Name, data, er.Attributes);
                    dllMod.Resources.Add(copy);
                    existing.Add(er.Name);
                    count++;
                }
            }
            catch {  }
            return count;
        }

        private void PromoteMembersToAssembly(ModuleDef module)
        {

            foreach (TypeDef type in module.GetTypes())
            {
                if (type == null) continue;
                if (type.Name == "<Module>" || type.IsGlobalModuleType) continue;
                if (engine.IsTypeUserExcluded(type)) continue;

                if (engine.injectedTypes.Contains(type)) continue;

                {
                    var tv = type.Attributes & DnTypeAttributes.VisibilityMask;
                    if (type.DeclaringType == null)
                    {
                        if (tv == DnTypeAttributes.NotPublic)
                        {
                            type.Attributes = (type.Attributes & ~DnTypeAttributes.VisibilityMask) | DnTypeAttributes.Public;
                        }
                    }
                    else
                    {
                        if (tv == DnTypeAttributes.NestedPrivate ||
                            tv == DnTypeAttributes.NestedAssembly ||
                            tv == DnTypeAttributes.NestedFamANDAssem ||
                            tv == DnTypeAttributes.NestedFamily ||
                            tv == DnTypeAttributes.NestedFamORAssem)
                        {
                            type.Attributes = (type.Attributes & ~DnTypeAttributes.VisibilityMask) | DnTypeAttributes.NestedPublic;
                        }
                    }
                }

                if (type.Fields != null)
                {
                    foreach (var f in type.Fields)
                    {
                        if (f == null) continue;
                        if (f.IsLiteral) continue;
                        var fa = f.Attributes & DnFieldAttributes.FieldAccessMask;
                        if (fa != DnFieldAttributes.Public)
                        {
                            f.Attributes = (f.Attributes & ~DnFieldAttributes.FieldAccessMask) | DnFieldAttributes.Public;
                        }
                    }
                }

                if (type.Methods != null)
                {
                    foreach (var m in type.Methods)
                    {
                        if (m == null) continue;
                        if (m.IsRuntimeSpecialName && !m.IsStaticConstructor) continue;

                        if (m.HasOverrides) continue;

                        var ma = m.Attributes & DnMethodAttributes.MemberAccessMask;
                        if (ma != DnMethodAttributes.Public)
                        {
                            m.Attributes = (m.Attributes & ~DnMethodAttributes.MemberAccessMask) | DnMethodAttributes.Public;
                        }
                    }
                }
            }
        }

        private void AddInternalsVisibleTo(ModuleDef module, string dllShortName)
        {
            try
            {
                var asm = module.Assembly;
                if (asm == null) return;
                var ivtRef = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "InternalsVisibleToAttribute");
                var ctorSig = MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String);
                var ctorRef = new MemberRefUser(module, ".ctor", ctorSig, ivtRef);
                var arg = new CAArgument(module.CorLibTypes.String, dllShortName);
                var ca = new CustomAttribute(ctorRef, new[] { arg });
                asm.CustomAttributes.Add(ca);
            }
            catch {  }
        }

        private bool IsBodyExportSafe(MethodDef m, ModuleDef exeModule)
        {
            if (m == null || m.Body == null) return false;
            foreach (var inst in m.Body.Instructions)
            {
                var mref = inst.Operand as IMethod;
                if (mref != null)
                {
                    var declType = mref.DeclaringType;
                    if (declType == null) continue;
                    var asTd = declType as TypeDef;
                    if (asTd != null && engine.injectedTypes.Contains(asTd))
                        return false;
                }

                var fref = inst.Operand as IField;
                if (fref != null)
                {
                    var declType = fref.DeclaringType;
                    if (declType == null) continue;
                    var asTd = declType as TypeDef;
                    if (asTd != null && engine.injectedTypes.Contains(asTd))
                        return false;
                }
            }
            return true;
        }

        private bool CanRelocate(MethodDef m)
        {
            if (m == null) return false;
            if (!m.HasBody || !m.Body.HasInstructions) return false;
            if (m.IsConstructor || m.IsStaticConstructor) return false;
            if (m.IsAbstract || m.IsVirtual) return false;
            if (m.HasOverrides) return false;
            if (m.IsRuntimeSpecialName) return false;
            if (m.IsPinvokeImpl) return false;
            if (m.HasGenericParameters) return false;
            if (m.DeclaringType == null) return false;
            if (m.DeclaringType.HasGenericParameters) return false;

            if (engine.IsMethodUserExcluded(m)) return false;
            if (m.Name == "Main") return false;
            if (m.Name == ".ctor" || m.Name == ".cctor") return false;
            if (!string.IsNullOrEmpty(m.Name) && m.Name.StartsWith("<")) return false;

            if (ReferencesGlobalModuleMember(m)) return false;
            return true;
        }

        private bool ReferencesGlobalModuleMember(MethodDef m)
        {
            if (m == null || m.Body == null || !m.Body.HasInstructions) return false;
            foreach (var inst in m.Body.Instructions)
            {
                if (inst.Operand == null) continue;
                ITypeDefOrRef declType = null;
                var mr = inst.Operand as IMethod;
                if (mr != null && mr.DeclaringType != null) declType = mr.DeclaringType;
                if (declType == null)
                {
                    var fr = inst.Operand as IField;
                    if (fr != null && fr.DeclaringType != null) declType = fr.DeclaringType;
                }
                if (declType == null) continue;

                var name = declType.Name;
                if (!UTF8String.IsNullOrEmpty(name) && name == "<Module>") return true;
            }
            return false;
        }

        private bool ReferencesLateRenamedInjectedType(MethodDef m)
        {
            if (m == null || m.Body == null || !m.Body.HasInstructions) return false;
            foreach (var inst in m.Body.Instructions)
            {
                if (inst.Operand == null) continue;
                ITypeDefOrRef declType = null;
                var mr = inst.Operand as IMethod;
                if (mr != null && mr.DeclaringType != null) declType = mr.DeclaringType;
                if (declType == null)
                {
                    var fr = inst.Operand as IField;
                    if (fr != null && fr.DeclaringType != null) declType = fr.DeclaringType;
                }
                if (declType == null)
                {
                    var tdor = inst.Operand as ITypeDefOrRef;
                    if (tdor != null) declType = tdor;
                }
                if (declType == null) continue;
                var resolved = declType as TypeDef;
                if (resolved == null)
                {
                    var asTr = declType as TypeRef;
                    if (asTr != null)
                    {
                        try { resolved = asTr.Resolve(); }
                        catch { resolved = null; }
                    }
                }
                if (resolved == null) continue;
                if (engine.injectedTypes.Contains(resolved)) return true;
            }
            return false;
        }

        private bool RelocateMethodToDll(MethodDef method, TypeDef holderType, ModuleDef dllMod, ModuleDef exeModule)
        {
            bool isInstance = !method.IsStatic;
            var dllImp = new Importer(dllMod);

            TypeSig declSig = null;
            if (isInstance)
            {
                try { declSig = dllImp.Import(method.DeclaringType.ToTypeSig()); }
                catch { return false; }
                if (declSig == null) return false;
            }

            var oldSig = method.MethodSig;
            var newParams = new List<TypeSig>();
            if (isInstance) newParams.Add(declSig);
            for (int i = 0; i < oldSig.Params.Count; i++)
            {
                var imported = dllImp.Import(oldSig.Params[i]);
                if (imported == null) return false;
                newParams.Add(imported);
            }
            var importedRet = dllImp.Import(oldSig.RetType);
            if (importedRet == null) return false;

            var helperSig = MethodSig.CreateStatic(importedRet, newParams.ToArray());
            var helper = new MethodDefUser(engine.MakeName(), helperSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Public | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            helper.Body = new CilBody();
            helper.Body.InitLocals = method.Body.InitLocals;

            foreach (var local in method.Body.Variables)
            {
                var imported = dllImp.Import(local.Type);
                if (imported == null) return false;
                helper.Body.Variables.Add(new Local(imported));
            }

            var instMap = new Dictionary<Instruction, Instruction>();
            foreach (var inst in method.Body.Instructions)
            {
                var clone = Instruction.Create(DnOpCodes.Nop);
                clone.OpCode = inst.OpCode;
                clone.Operand = inst.Operand;
                instMap[inst] = clone;
                helper.Body.Instructions.Add(clone);
            }

            foreach (var inst in helper.Body.Instructions)
            {
                if (inst.Operand == null) continue;

                Instruction target = inst.Operand as Instruction;
                if (target != null)
                {
                    Instruction mapped;
                    if (instMap.TryGetValue(target, out mapped)) inst.Operand = mapped;
                    continue;
                }

                Instruction[] targets = inst.Operand as Instruction[];
                if (targets != null)
                {
                    var newTargets = new Instruction[targets.Length];
                    for (int t = 0; t < targets.Length; t++)
                    {
                        Instruction mapped;
                        if (instMap.TryGetValue(targets[t], out mapped)) newTargets[t] = mapped;
                        else newTargets[t] = targets[t];
                    }
                    inst.Operand = newTargets;
                    continue;
                }

                var p = inst.Operand as Parameter;
                if (p != null)
                {
                    int idx = p.Index;
                    if (idx >= 0 && idx < helper.Parameters.Count)
                        inst.Operand = helper.Parameters[idx];
                    continue;
                }

                var local = inst.Operand as Local;
                if (local != null)
                {
                    int idx = local.Index;
                    if (idx >= 0 && idx < helper.Body.Variables.Count)
                        inst.Operand = helper.Body.Variables[idx];
                    continue;
                }

                try
                {
                    var sig = inst.Operand as TypeSig;
                    if (sig != null) { inst.Operand = dllImp.Import(sig); continue; }

                    var td = inst.Operand as ITypeDefOrRef;
                    if (td != null) { inst.Operand = dllImp.Import(td.ToTypeSig()).ToTypeDefOrRef(); continue; }

                    var mr = inst.Operand as IMethod;
                    if (mr != null) { inst.Operand = dllImp.Import(mr); continue; }

                    var fr = inst.Operand as IField;
                    if (fr != null) { inst.Operand = dllImp.Import(fr); continue; }

                    var ms = inst.Operand as MethodSig;
                    if (ms != null)
                    {
                        var importedRetX = dllImp.Import(ms.RetType);
                        var importedParamsX = new TypeSig[ms.Params.Count];
                        for (int x = 0; x < ms.Params.Count; x++)
                            importedParamsX[x] = dllImp.Import(ms.Params[x]);
                        var newMs = new MethodSig(ms.CallingConvention, ms.GenParamCount, importedRetX, importedParamsX);
                        inst.Operand = newMs;
                        continue;
                    }
                }
                catch
                {
                    return false;
                }
            }

            if (method.Body.HasExceptionHandlers)
            {
                foreach (var origEh in method.Body.ExceptionHandlers)
                {
                    var newEh = new ExceptionHandler(origEh.HandlerType);
                    Instruction mapped;
                    if (origEh.TryStart != null && instMap.TryGetValue(origEh.TryStart, out mapped))
                        newEh.TryStart = mapped;
                    if (origEh.TryEnd != null && instMap.TryGetValue(origEh.TryEnd, out mapped))
                        newEh.TryEnd = mapped;
                    if (origEh.HandlerStart != null && instMap.TryGetValue(origEh.HandlerStart, out mapped))
                        newEh.HandlerStart = mapped;
                    if (origEh.HandlerEnd != null && instMap.TryGetValue(origEh.HandlerEnd, out mapped))
                        newEh.HandlerEnd = mapped;
                    if (origEh.FilterStart != null && instMap.TryGetValue(origEh.FilterStart, out mapped))
                        newEh.FilterStart = mapped;
                    if (origEh.CatchType != null)
                    {
                        try { newEh.CatchType = dllImp.Import(origEh.CatchType.ToTypeSig()).ToTypeDefOrRef(); }
                        catch { return false; }
                    }
                    helper.Body.ExceptionHandlers.Add(newEh);
                }
            }

            holderType.Methods.Add(helper);

            var dllAsm = dllMod.Assembly;
            var dllAsmRef = new AssemblyRefUser(dllAsm.Name, dllAsm.Version,
                dllAsm.PublicKeyOrToken, dllAsm.Culture);
            exeModule.UpdateRowId(dllAsmRef);

            var holderTypeRef = new TypeRefUser(exeModule, holderType.Namespace ?? UTF8String.Empty,
                holderType.Name, dllAsmRef);
            exeModule.UpdateRowId(holderTypeRef);

            var newParamsExeView = new List<TypeSig>();
            if (isInstance) newParamsExeView.Add(method.DeclaringType.ToTypeSig());
            for (int p = 0; p < oldSig.Params.Count; p++)
                newParamsExeView.Add(oldSig.Params[p]);

            var helperSigExe = MethodSig.CreateStatic(oldSig.RetType, newParamsExeView.ToArray());

            var helperRef = new MemberRefUser(exeModule, helper.Name, helperSigExe, holderTypeRef);
            exeModule.UpdateRowId(helperRef);

            method.Body = new CilBody();
            method.Body.InitLocals = false;
            var il = method.Body.Instructions;
            for (int i = 0; i < method.Parameters.Count; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldarg, method.Parameters[i]));
            }
            il.Add(Instruction.Create(DnOpCodes.Call, helperRef));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            engine.injectedMethods.Add(method);

            return true;
        }
    }
}
