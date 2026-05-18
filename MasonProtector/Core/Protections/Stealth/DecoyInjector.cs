using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
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
    internal class DecoyInjectorProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal DecoyInjectorProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyDecoyInjection(ModuleDef module, TypeDef modType)
        {
            int decoyTypeCount = rng.Next(12, 28);
            for (int i = 0; i < decoyTypeCount; i++)
            {
                BuildDecoyShroudType(module, modType);
            }

            int decoyPopulatorCount = rng.Next(8, 18);
            for (int i = 0; i < decoyPopulatorCount; i++)
            {
                BuildDecoyPopulator(module, modType);
            }

            int decoyVaultCount = rng.Next(6, 14);
            for (int i = 0; i < decoyVaultCount; i++)
            {
                BuildDecoyVaultType(module, modType);
            }
        }

        private void BuildDecoyShroudType(ModuleDef module, TypeDef modType)
        {
            TypeDef shroud = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            shroud.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(shroud);
            engine.injectedTypes.Add(shroud);

            int saltLen = rng.Next(8, 32);
            byte[] salt = engine.CryptoRandom(saltLen);
            byte[] mask = engine.CryptoRandom(rng.Next(16, 48));
            byte[] blob = engine.CryptoRandom(rng.Next(40, 600) * 8);

            EmitRvaField(module, shroud, salt, "_s");
            EmitRvaField(module, shroud, mask, "_m");
            EmitRvaField(module, shroud, blob, "_b");

            FieldDef state = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            shroud.Fields.Add(state);

            FieldDef cache = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.UInt64),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            shroud.Fields.Add(cache);

            FieldDef lockObj = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Object),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            shroud.Fields.Add(lockObj);

            BuildDecoyHash(module, shroud, cache);
            BuildDecoyContains(module, shroud, cache);
            BuildDecoyScanString(module, shroud);
            BuildDecoyKill(module, shroud);

            MaybeAddDecoyPInvoke(module, shroud);

            MethodDef cctor = new MethodDefUser(".cctor",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static |
                DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                DnMethodAttributes.RTSpecialName);
            cctor.Body = new CilBody();
            var cIl = cctor.Body.Instructions;

            MemberRefUser objCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                module.CorLibTypes.Object.TypeDefOrRef);
            cIl.Add(Instruction.Create(DnOpCodes.Newobj, objCtor));
            cIl.Add(Instruction.Create(DnOpCodes.Stsfld, lockObj));

            cIl.Add(engine.LoadInt(rng.Next()));
            cIl.Add(Instruction.Create(DnOpCodes.Stsfld, state));

            cIl.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)NextNoise()));
            cIl.Add(Instruction.Create(DnOpCodes.Stsfld, cache));

            cIl.Add(Instruction.Create(DnOpCodes.Ret));
            shroud.Methods.Add(cctor);
            engine.injectedMethods.Add(cctor);
        }

        private void BuildDecoyHash(ModuleDef module, TypeDef owner, FieldDef cache)
        {
            MethodDef m = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.UInt64,
                    new SZArraySig(module.CorLibTypes.Byte),
                    module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            m.Body.InitLocals = true;
            m.Body.Variables.Add(new Local(module.CorLibTypes.UInt64));
            m.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            IList<Instruction> il = m.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, cache));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            Instruction loopCond = Instruction.Create(DnOpCodes.Ldloc_1);
            il.Add(Instruction.Create(DnOpCodes.Br, loopCond));

            Instruction loopBody = Instruction.Create(DnOpCodes.Ldloc_0);
            il.Add(loopBody);
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldelem_U1));
            il.Add(Instruction.Create(DnOpCodes.Conv_U8));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)NextNoise()));
            il.Add(Instruction.Create(DnOpCodes.Mul));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            il.Add(loopCond);
            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            il.Add(Instruction.Create(DnOpCodes.Blt, loopBody));

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            owner.Methods.Add(m);
            engine.injectedMethods.Add(m);
        }

        private void BuildDecoyContains(ModuleDef module, TypeDef owner, FieldDef cache)
        {
            MethodDef m = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.UInt64),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            IList<Instruction> il = m.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldsfld, cache));
            il.Add(Instruction.Create(DnOpCodes.Ceq));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            owner.Methods.Add(m);
            engine.injectedMethods.Add(m);
        }

        private void BuildDecoyScanString(ModuleDef module, TypeDef owner)
        {
            MethodDef m = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            IList<Instruction> il = m.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Pop));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            owner.Methods.Add(m);
            engine.injectedMethods.Add(m);
        }

        private void BuildDecoyKill(ModuleDef module, TypeDef owner)
        {
            MethodDef m = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            m.Body = new CilBody();
            IList<Instruction> il = m.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ret));
            owner.Methods.Add(m);
            engine.injectedMethods.Add(m);
        }

        private void MaybeAddDecoyPInvoke(ModuleDef module, TypeDef owner)
        {
            if (rng.Next(0, 4) != 0) return;
            string[] candidates = new string[] {
                "GetTickCount", "GetCurrentThreadId", "GetCurrentProcessId",
                "GetSystemTimeAsFileTime", "QueryPerformanceCounter"
            };
            string ep = candidates[rng.Next(candidates.Length)];
            ModuleRef kernel32 = GetOrCreateModuleRef(module, "kernel32.dll");
            MethodSig sig;
            if (ep == "QueryPerformanceCounter")
                sig = MethodSig.CreateStatic(module.CorLibTypes.Boolean, new ByRefSig(module.CorLibTypes.Int64));
            else
                sig = MethodSig.CreateStatic(module.CorLibTypes.UInt32);
            MethodDefUser pm = new MethodDefUser(engine.MakeName(),
                sig,
                DnMethodImplAttributes.PreserveSig,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static |
                DnMethodAttributes.PinvokeImpl | DnMethodAttributes.HideBySig);
            pm.ImplMap = new ImplMapUser(kernel32, ep,
                PInvokeAttributes.CallConvStdCall | PInvokeAttributes.NoMangle);
            owner.Methods.Add(pm);
            engine.injectedMethods.Add(pm);
        }

        private void BuildDecoyPopulator(ModuleDef module, TypeDef modType)
        {
            TypeDef host = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(host);
            engine.injectedTypes.Add(host);

            int slotCount = rng.Next(20, 120);

            FieldDef mhArr = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.Import(typeof(RuntimeMethodHandle)).ToTypeSig())),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            host.Fields.Add(mhArr);

            FieldDef thArr = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.Import(typeof(RuntimeTypeHandle)).ToTypeSig())),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            host.Fields.Add(thArr);

            FieldDef pepperField = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            host.Fields.Add(pepperField);

            byte[] pepper = engine.CryptoRandom(rng.Next(64, 160));
            FieldDef pepperRva = CreateRvaSource(module, host, pepper);

            FieldDef iterField = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.Int32),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            host.Fields.Add(iterField);

            MethodDef cctor = new MethodDefUser(".cctor",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static |
                DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                DnMethodAttributes.RTSpecialName);
            cctor.Body = new CilBody();
            IList<Instruction> il = cctor.Body.Instructions;

            Importer importer = new Importer(module);
            IMethod rhInitArr = importer.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers)
                .GetMethod("InitializeArray",
                    new Type[] { typeof(Array), typeof(RuntimeFieldHandle) }));
            ITypeDefOrRef sysByte = importer.Import(typeof(byte));

            il.Add(engine.LoadInt(pepper.Length));
            il.Add(Instruction.Create(DnOpCodes.Newarr, sysByte));
            il.Add(Instruction.Create(DnOpCodes.Dup));
            il.Add(Instruction.Create(DnOpCodes.Ldtoken, pepperRva));
            il.Add(Instruction.Create(DnOpCodes.Call, rhInitArr));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, pepperField));

            il.Add(engine.LoadInt(slotCount));
            il.Add(Instruction.Create(DnOpCodes.Newarr, importer.Import(typeof(RuntimeMethodHandle))));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, mhArr));

            il.Add(engine.LoadInt(slotCount));
            il.Add(Instruction.Create(DnOpCodes.Newarr, importer.Import(typeof(RuntimeTypeHandle))));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, thArr));

            il.Add(engine.LoadInt(rng.Next(100000, 600000)));
            il.Add(Instruction.Create(DnOpCodes.Stsfld, iterField));

            il.Add(Instruction.Create(DnOpCodes.Ret));
            host.Methods.Add(cctor);
            engine.injectedMethods.Add(cctor);
        }

        private void BuildDecoyVaultType(ModuleDef module, TypeDef modType)
        {
            TypeDef vt = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            vt.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(vt);
            engine.injectedTypes.Add(vt);

            FieldDef fFile = new FieldDefUser(engine.MakeName(),
                new FieldSig(module.CorLibTypes.String),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vt.Fields.Add(fFile);

            FieldDef fSeed = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vt.Fields.Add(fSeed);

            FieldDef fMask1 = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vt.Fields.Add(fMask1);

            FieldDef fMask2 = new FieldDefUser(engine.MakeName(),
                new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vt.Fields.Add(fMask2);

            byte[] seedBytes = engine.CryptoRandom(176);
            byte[] mask1Bytes = engine.CryptoRandom(176);
            byte[] mask2Bytes = engine.CryptoRandom(176);

            EmitRvaField(module, vt, seedBytes, "");
            EmitRvaField(module, vt, mask1Bytes, "");
            EmitRvaField(module, vt, mask2Bytes, "");

            MethodDef getStream = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.Import(typeof(System.IO.Stream)).ToTypeSig(),
                    module.Import(typeof(System.Reflection.Assembly)).ToTypeSig(),
                    module.CorLibTypes.String),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            getStream.Body = new CilBody();
            IList<Instruction> il = getStream.Body.Instructions;
            il.Add(Instruction.Create(DnOpCodes.Ldnull));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            vt.Methods.Add(getStream);
            engine.injectedMethods.Add(getStream);

            string namesTaken = engine.MakeName();
            FieldDef decoyName = new FieldDefUser(namesTaken,
                new FieldSig(module.CorLibTypes.Object),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static);
            vt.Fields.Add(decoyName);
        }

        private FieldDef CreateRvaSource(ModuleDef module, TypeDef owner, byte[] bytes)
        {
            Importer importer = new Importer(module);
            ITypeDefOrRef sysValueType = importer.Import(typeof(ValueType));
            TypeDef holder = new TypeDefUser("", engine.MakeName(), sysValueType);
            holder.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.SequentialLayout | DnTypeAttributes.Sealed;
            holder.ClassLayout = new ClassLayoutUser(1, (uint)bytes.Length);
            owner.NestedTypes.Add(holder);
            engine.injectedTypes.Add(holder);

            FieldDef rvaField = new FieldDefUser(engine.MakeName(),
                new FieldSig(holder.ToTypeSig()),
                DnFieldAttributes.Assembly | DnFieldAttributes.Static | DnFieldAttributes.HasFieldRVA);
            rvaField.HasFieldRVA = true;
            rvaField.InitialValue = (byte[])bytes.Clone();
            owner.Fields.Add(rvaField);
            return rvaField;
        }

        private void EmitRvaField(ModuleDef module, TypeDef owner, byte[] bytes, string namePrefix)
        {
            CreateRvaSource(module, owner, bytes);
        }

        private ModuleRef GetOrCreateModuleRef(ModuleDef module, string dll)
        {
            foreach (ModuleRef mr in module.GetModuleRefs())
            {
                if (mr.Name == dll) return mr;
            }
            return new ModuleRefUser(module, dll);
        }

        private ulong NextNoise()
        {
            ulong h = ((ulong)(uint)rng.Next() << 32) | (ulong)(uint)rng.Next();
            return h | 1UL;
        }
    }
}

