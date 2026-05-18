using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class LibraryMergingProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal LibraryMergingProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal int ApplyLibraryMerging(ModuleDef module, TypeDef modType, List<string> libraryPaths)
        {
            if (libraryPaths == null || libraryPaths.Count == 0) return 0;

            var resourceMap = new Dictionary<string, string>();
            int merged = 0;

            foreach (string libPath in libraryPaths)
            {
                if (string.IsNullOrEmpty(libPath) || !File.Exists(libPath)) continue;
                try
                {
                    byte[] raw = File.ReadAllBytes(libPath);
                    if (raw.Length == 0) continue;

                    string assemblyName = TryGetAssemblyFullName(libPath);
                    if (string.IsNullOrEmpty(assemblyName)) assemblyName = Path.GetFileNameWithoutExtension(libPath);

                    byte[] compressed;
                    using (var ms = new MemoryStream())
                    {
                        using (var ds = new DeflateStream(ms, CompressionMode.Compress, true))
                            ds.Write(raw, 0, raw.Length);
                        compressed = ms.ToArray();
                    }

                    byte xorKey = (byte)rng.Next(1, 255);
                    for (int i = 0; i < compressed.Length; i++)
                        compressed[i] ^= (byte)(xorKey ^ (i & 0xFF));

                    byte[] header = new byte[compressed.Length + 1];
                    header[0] = xorKey;
                    Buffer.BlockCopy(compressed, 0, header, 1, compressed.Length);

                    string resName = "$Merged_" + engine.MakeName().Replace(".", "_");
                    module.Resources.Add(new EmbeddedResource(resName, header,
                        ManifestResourceAttributes.Private));
                    engine.injectedResources.Add(resName);
                    resourceMap[assemblyName] = resName;
                    merged++;
                }
                catch { }
            }

            if (merged == 0) return 0;

            BuildResolver(module, modType, resourceMap);
            return merged;
        }

        private string TryGetAssemblyFullName(string path)
        {
            try
            {
                using (var mod = ModuleDefMD.Load(path))
                {
                    if (mod.Assembly != null) return mod.Assembly.GetFullNameWithPublicKeyToken();
                    return mod.Name;
                }
            }
            catch { return null; }
        }

        private void BuildResolver(ModuleDef module, TypeDef modType, Dictionary<string, string> map)
        {
            var nameToRes = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.String)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            modType.Fields.Add(nameToRes);

            var resToData = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.String)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            modType.Fields.Add(resToData);

            var registered = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Boolean),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            modType.Fields.Add(registered);

            var resolverMethod = BuildResolverMethod(module, modType, nameToRes, resToData);
            modType.Methods.Add(resolverMethod);
            engine.injectedMethods.Add(resolverMethod);

            var initMethod = BuildResolverInit(module, modType, nameToRes, resToData, registered, resolverMethod, map);
            modType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);

            engine.InjectCallAtTop(module, modType, initMethod);
        }

        private MethodDef BuildResolverInit(ModuleDef module, TypeDef modType,
            FieldDef nameToRes, FieldDef resToData, FieldDef registered,
            MethodDef resolverMethod, Dictionary<string, string> map)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            var il = method.Body.Instructions;

            var alreadyDone = Instruction.Create(DnOpCodes.Ret);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, registered));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, alreadyDone));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, registered));

            var keys = map.Keys.ToList();
            il.Add(engine.LoadInt(keys.Count));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.String.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, nameToRes));

            il.Add(engine.LoadInt(keys.Count));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.String.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, resToData));

            for (int i = 0; i < keys.Count; i++)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldsfld, nameToRes));
                il.Add(engine.LoadInt(i));
                il.Add(Instruction.Create(DnOpCodes.Ldstr, keys[i]));
                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));

                il.Add(Instruction.Create(DnOpCodes.Ldsfld, resToData));
                il.Add(engine.LoadInt(i));
                il.Add(Instruction.Create(DnOpCodes.Ldstr, map[keys[i]]));
                il.Add(Instruction.Create(DnOpCodes.Stelem_Ref));
            }

            var getCurrentDomain = module.Import(typeof(System.AppDomain).GetProperty("CurrentDomain").GetGetMethod());
            var resolveEventHandler = module.Import(typeof(System.ResolveEventHandler));
            var resolveHandlerCtor = module.Import(typeof(System.ResolveEventHandler).GetConstructor(
                new[] { typeof(object), typeof(IntPtr) }));
            var addAssemblyResolve = module.Import(typeof(System.AppDomain).GetEvent("AssemblyResolve").GetAddMethod());

            il.Add(Instruction.Create(DnOpCodes.Call, getCurrentDomain));
            il.Add(Instruction.Create(DnOpCodes.Ldnull));
            il.Add(Instruction.Create(DnOpCodes.Ldftn, resolverMethod));
            il.Add(Instruction.Create(DnOpCodes.Newobj, resolveHandlerCtor));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, addAssemblyResolve));

            il.Add(alreadyDone);

            return method;
        }

        private MethodDef BuildResolverMethod(ModuleDef module, TypeDef modType,
            FieldDef nameToRes, FieldDef resToData)
        {
            var assemblyRef = module.Import(typeof(System.Reflection.Assembly)).ToTypeSig();
            var resolveEventArgs = module.Import(typeof(System.ResolveEventArgs)).ToTypeSig();

            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(assemblyRef, module.CorLibTypes.Object, resolveEventArgs),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.String));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.String));
            method.Body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Byte)));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Byte));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;

            var getName = module.Import(typeof(System.ResolveEventArgs).GetProperty("Name").GetGetMethod());
            var stringContains = module.Import(typeof(string).GetMethod("StartsWith", new[] { typeof(string) }));
            var getExecAsm = module.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly", Type.EmptyTypes));
            var getManifestResStream = module.Import(typeof(System.Reflection.Assembly).GetMethod("GetManifestResourceStream", new[] { typeof(string) }));
            var streamReadByte = module.Import(typeof(System.IO.Stream).GetMethod("ReadByte"));
            var streamLength = module.Import(typeof(System.IO.Stream).GetProperty("Length").GetGetMethod());
            var streamRead = module.Import(typeof(System.IO.Stream).GetMethod("Read", new[] { typeof(byte[]), typeof(int), typeof(int) }));
            var deflateCtor = module.Import(typeof(System.IO.Compression.DeflateStream).GetConstructor(new[] { typeof(System.IO.Stream), typeof(System.IO.Compression.CompressionMode) }));
            var msCtor = module.Import(typeof(System.IO.MemoryStream).GetConstructor(new[] { typeof(byte[]) }));
            var msToArray = module.Import(typeof(System.IO.MemoryStream).GetMethod("ToArray", Type.EmptyTypes));
            var msCopyTo = module.Import(typeof(System.IO.Stream).GetMethod("CopyTo", new[] { typeof(System.IO.Stream) }));
            var msCtorEmpty = module.Import(typeof(System.IO.MemoryStream).GetConstructor(Type.EmptyTypes));
            var asmLoad = module.Import(typeof(System.Reflection.Assembly).GetMethod("Load", new[] { typeof(byte[]) }));

            var notFound = Instruction.Create(DnOpCodes.Ldnull);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getName));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, nameToRes));
            il.Add(Instruction.Create(DnOpCodes.Brfalse, notFound));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var loopStart = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, loopStart));

            var loopBody = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(loopBody);

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, nameToRes));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, stringContains));

            var skipIter = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Brfalse, skipIter));

            il.Add(Instruction.Create(DnOpCodes.Ldsfld, resToData));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_Ref));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));

            il.Add(Instruction.Create(DnOpCodes.Call, getExecAsm));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, getManifestResStream));

            il.Add(Instruction.Create(DnOpCodes.Dup));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, streamReadByte));
            il.Add(Instruction.Create(DnOpCodes.Conv_U1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[4]));

            il.Add(Instruction.Create(DnOpCodes.Dup));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, streamLength));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, method.Body.Variables[5]));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[5]));
            il.Add(Instruction.Create(DnOpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[5]));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, streamRead));
            il.Add(Instruction.Create(DnOpCodes.Pop));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            var dexorStart = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, dexorStart));

            var dexorBody = Instruction.Create(DnOpCodes.Ldloc_3);
            il.Add(dexorBody);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[4]));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 0xFF));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Conv_U1));
            il.Add(Instruction.Create(DnOpCodes.Stelem_I1));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(dexorStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, method.Body.Variables[5]));
            il.Add(Instruction.Create(DnOpCodes.Blt, dexorBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Newobj, msCtor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)System.IO.Compression.CompressionMode.Decompress));
            il.Add(Instruction.Create(DnOpCodes.Newobj, deflateCtor));

            il.Add(Instruction.Create(DnOpCodes.Newobj, msCtorEmpty));
            il.Add(Instruction.Create(DnOpCodes.Dup));

            var tempLocal = new Local(module.Import(typeof(System.IO.MemoryStream)).ToTypeSig());
            method.Body.Variables.Add(tempLocal);
            il.Add(Instruction.Create(DnOpCodes.Stloc_S, tempLocal));

            il.Add(Instruction.Create(DnOpCodes.Callvirt, msCopyTo));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_S, tempLocal));
            il.Add(Instruction.Create(DnOpCodes.Callvirt, msToArray));
            il.Add(Instruction.Create(DnOpCodes.Call, asmLoad));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            il.Add(skipIter);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(loopStart);
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, nameToRes));
            il.Add(Instruction.Create(DnOpCodes.Ldlen));
            il.Add(Instruction.Create(DnOpCodes.Conv_I4));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(notFound);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }
    }
}

