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
    internal class EntryPointMoverProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal EntryPointMoverProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyEntryPointMover(ModuleDef module, TypeDef modType)
        {
            MethodDef original = module.EntryPoint;
            if (original == null) return;
            if (!original.HasBody) return;
            if (original.IsStatic == false) return;

            TypeSig retSig = original.MethodSig.RetType;
            bool returnsInt = retSig != null && retSig.FullName == "System.Int32";
            bool returnsVoid = retSig != null && retSig.FullName == "System.Void";
            if (!returnsInt && !returnsVoid) return;

            bool takesArgs = original.MethodSig.Params != null && original.MethodSig.Params.Count == 1;
            if (original.MethodSig.Params != null && original.MethodSig.Params.Count > 1) return;
            if (takesArgs)
            {
                var p0 = original.MethodSig.Params[0];
                if (p0.FullName != "System.String[]") return;
            }

            ICustomAttributeType staCtorRef = null;
            ICustomAttributeType mtaCtorRef = null;
            bool wantSta = false;
            bool wantMta = false;
            if (original.HasCustomAttributes)
            {
                foreach (var ca in original.CustomAttributes)
                {
                    if (ca.AttributeType == null) continue;
                    string af = ca.AttributeType.FullName;
                    if (af == "System.STAThreadAttribute") wantSta = true;
                    else if (af == "System.MTAThreadAttribute") wantMta = true;
                }
            }
            try
            {
                if (wantSta)
                {
                    var ci = typeof(System.STAThreadAttribute).GetConstructor(Type.EmptyTypes);
                    if (ci != null) staCtorRef = (ICustomAttributeType)module.Import(ci);
                }
                if (wantMta)
                {
                    var ci = typeof(System.MTAThreadAttribute).GetConstructor(Type.EmptyTypes);
                    if (ci != null) mtaCtorRef = (ICustomAttributeType)module.Import(ci);
                }
            }
            catch { }

            TypeDef trampolineHost = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            trampolineHost.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(trampolineHost);
            engine.injectedTypes.Add(trampolineHost);

            int hops = rng.Next(7, 14);

            FieldDef[] saltField = new FieldDef[hops];
            int[] saltSeed = new int[hops];
            for (int i = 0; i < hops; i++)
            {
                saltSeed[i] = rng.Next(0x10000, int.MaxValue / 4);
                saltField[i] = new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static);
                trampolineHost.Fields.Add(saltField[i]);
            }

            MethodDef saltCctor = new MethodDefUser(".cctor",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Private | DnMethodAttributes.Static |
                DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                DnMethodAttributes.RTSpecialName);
            saltCctor.Body = new CilBody();
            var sIl = saltCctor.Body.Instructions;
            for (int i = 0; i < hops; i++)
            {
                int mask = rng.Next(int.MinValue, int.MaxValue);
                sIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, mask));
                sIl.Add(Instruction.Create(DnOpCodes.Ldc_I4, mask ^ saltSeed[i]));
                sIl.Add(Instruction.Create(DnOpCodes.Xor));
                sIl.Add(Instruction.Create(DnOpCodes.Stsfld, saltField[i]));
            }
            sIl.Add(Instruction.Create(DnOpCodes.Ret));
            trampolineHost.Methods.Add(saltCctor);
            engine.injectedMethods.Add(saltCctor);

            MethodDef tail = original;

            if (tail.IsPrivate || tail.IsFamily || tail.IsFamilyAndAssembly || tail.IsFamilyOrAssembly || tail.IsCompilerControlled)
            {
                tail.Attributes &= ~DnMethodAttributes.MemberAccessMask;
                tail.Attributes |= DnMethodAttributes.Assembly;
            }
            if (tail.DeclaringType != null)
            {
                TypeDef ownerWalk = tail.DeclaringType;
                while (ownerWalk != null)
                {
                    if (ownerWalk.IsNested)
                    {
                        if (ownerWalk.IsNestedPrivate || ownerWalk.IsNestedFamily ||
                            ownerWalk.IsNestedFamilyAndAssembly || ownerWalk.IsNestedFamilyOrAssembly)
                        {
                            ownerWalk.Attributes &= ~DnTypeAttributes.VisibilityMask;
                            ownerWalk.Attributes |= DnTypeAttributes.NestedAssembly;
                        }
                    }
                    ownerWalk = ownerWalk.DeclaringType;
                }
            }

            for (int hop = 0; hop < hops; hop++)
            {
                MethodSig sig;
                if (takesArgs)
                {
                    if (returnsInt)
                        sig = MethodSig.CreateStatic(module.CorLibTypes.Int32,
                            new SZArraySig(module.CorLibTypes.String));
                    else
                        sig = MethodSig.CreateStatic(module.CorLibTypes.Void,
                            new SZArraySig(module.CorLibTypes.String));
                }
                else
                {
                    if (returnsInt)
                        sig = MethodSig.CreateStatic(module.CorLibTypes.Int32);
                    else
                        sig = MethodSig.CreateStatic(module.CorLibTypes.Void);
                }

                MethodDef shim = new MethodDefUser(engine.MakeName(), sig,
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed |
                    DnMethodImplAttributes.NoInlining,
                    DnMethodAttributes.Private | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig);

                shim.Body = new CilBody();
                shim.Body.InitLocals = true;
                if (returnsInt)
                    shim.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
                shim.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

                var il = shim.Body.Instructions;

                EmitHopJunk(il, saltField[hop], saltSeed[hop], shim.Body.Variables[returnsInt ? 1 : 0]);

                if (takesArgs)
                    il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                il.Add(Instruction.Create(DnOpCodes.Call, tail));

                if (returnsInt)
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));

                EmitHopJunk(il, saltField[hop], saltSeed[hop] ^ 0x5A5A5A5A, shim.Body.Variables[returnsInt ? 1 : 0]);

                if (returnsInt)
                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                il.Add(Instruction.Create(DnOpCodes.Ret));

                trampolineHost.Methods.Add(shim);
                engine.injectedMethods.Add(shim);
                tail = shim;
            }

            try
            {
                if (staCtorRef != null)
                    tail.CustomAttributes.Add(new CustomAttribute(staCtorRef));
                else if (mtaCtorRef != null)
                    tail.CustomAttributes.Add(new CustomAttribute(mtaCtorRef));
            }
            catch { }

            module.EntryPoint = tail;
        }

        private void EmitHopJunk(IList<Instruction> il, FieldDef salt, int magic, Local scratch)
        {
            int variant = rng.Next(0, 3);
            switch (variant)
            {
                case 0:
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, salt));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, magic));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Stloc, scratch));
                    break;
                }
                case 1:
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, salt));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, magic));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, magic));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Stloc, scratch));
                    break;
                }
                default:
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldsfld, salt));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, magic));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Stloc, scratch));
                    break;
                }
            }
        }
    }
}

