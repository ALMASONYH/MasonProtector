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
    internal class MethodScatteringProtection
    {
        private Obfuscation engine;
        private Random rng;

        private const int SCATTER_HOST_COUNT = 24;
        private const int SCATTER_BRIDGE_COUNT = 36;
        private const int SCATTER_FAKE_COUNT = 32;
        private const int SCATTER_FIELD_NOISE = 48;
        private const int SCATTER_DECOY_TYPE_COUNT = 14;

        private List<TypeDef> scatterHosts;
        private List<MethodDef> bridgeMethods;
        private List<TypeDef> decoyTypes;

        internal MethodScatteringProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyMethodScattering(ModuleDef module, TypeDef modType)
        {
            scatterHosts = new List<TypeDef>();
            bridgeMethods = new List<MethodDef>();
            decoyTypes = new List<TypeDef>();

            CreateScatterHosts(module);
            CreateDecoyTypes(module);
            InjectFieldNoise(module);

            int counter = 0;
            foreach (TypeDef type in module.GetTypes().ToList())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods.ToList())
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (method.IsConstructor || method.IsStaticConstructor) continue;
                    if (!method.IsStatic) continue;
                    if (method == module.EntryPoint) continue;
                    if (method.Parameters.Count > 4) continue;
                    if (method.MethodSig == null) continue;
                    if (method.MethodSig.RetType == null) continue;
                    if (engine.MethodHasAsyncOrIteratorAttribute(method)) continue;
                    if (HasPrivateFieldAccess(method, type)) continue;
                    if (HasNestedTypeAccess(method, type)) continue;
                    if (rng.Next(0, 5) != 0) continue;
                    try
                    {
                        if (ScatterMethod(module, method))
                            counter++;
                    }
                    catch { }
                }
            }

            CreateBridgeMethods(module);
            CreateFakeMethods(module);
            InjectDecoyMethodNoise(module);
        }

        private void CreateScatterHosts(ModuleDef module)
        {
            for (int h = 0; h < SCATTER_HOST_COUNT; h++)
            {
                var host = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(host);
                engine.injectedTypes.Add(host);
                scatterHosts.Add(host);

                for (int f = 0; f < rng.Next(3, 7); f++)
                {
                    TypeSig fieldType;
                    int t = rng.Next(0, 4);
                    if (t == 0) fieldType = module.CorLibTypes.Int32;
                    else if (t == 1) fieldType = module.CorLibTypes.Int64;
                    else if (t == 2) fieldType = module.CorLibTypes.Boolean;
                    else fieldType = module.CorLibTypes.Byte;

                    host.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(fieldType),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }
            }
        }

        private void CreateDecoyTypes(ModuleDef module)
        {
            for (int d = 0; d < SCATTER_DECOY_TYPE_COUNT; d++)
            {
                var decoy = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                decoy.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(decoy);
                engine.injectedTypes.Add(decoy);
                decoyTypes.Add(decoy);

                for (int f = 0; f < rng.Next(4, 10); f++)
                {
                    TypeSig ft;
                    int t = rng.Next(0, 5);
                    if (t == 0) ft = module.CorLibTypes.Int32;
                    else if (t == 1) ft = module.CorLibTypes.Int64;
                    else if (t == 2) ft = module.CorLibTypes.String;
                    else if (t == 3) ft = module.CorLibTypes.Boolean;
                    else ft = module.CorLibTypes.Double;

                    decoy.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(ft),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 7); m++)
                {
                    var fakeMethod = BuildDecoyComputeMethod(module);
                    decoy.Methods.Add(fakeMethod);
                    engine.injectedMethods.Add(fakeMethod);
                }
            }
        }

        private void InjectFieldNoise(ModuleDef module)
        {
            var allHosts = new List<TypeDef>();
            allHosts.AddRange(scatterHosts);
            allHosts.AddRange(decoyTypes);

            for (int i = 0; i < SCATTER_FIELD_NOISE; i++)
            {
                var host = allHosts[rng.Next(allHosts.Count)];
                TypeSig ft;
                int t = rng.Next(0, 5);
                if (t == 0) ft = module.CorLibTypes.Int32;
                else if (t == 1) ft = new SZArraySig(module.CorLibTypes.Int32);
                else if (t == 2) ft = module.CorLibTypes.Int64;
                else if (t == 3) ft = module.CorLibTypes.Byte;
                else ft = new SZArraySig(module.CorLibTypes.Byte);

                host.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(ft),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private bool HasNestedTypeAccess(MethodDef method, TypeDef declaringType)
        {
            if (!method.HasBody) return false;
            foreach (var instr in method.Body.Instructions)
            {
                var ot = instr.OpCode.OperandType;
                ITypeDefOrRef refType = null;
                var fieldRef = instr.Operand as IField;
                if (fieldRef != null) refType = fieldRef.DeclaringType;
                var methodRef = instr.Operand as IMethod;
                if (methodRef != null && refType == null) refType = methodRef.DeclaringType;
                var typeRef = instr.Operand as ITypeDefOrRef;
                if (typeRef != null && refType == null) refType = typeRef;
                if (refType == null) continue;
                var td = refType.ResolveTypeDef();
                if (td == null) continue;
                var owner = td.DeclaringType;
                while (owner != null)
                {
                    if (owner == declaringType) return true;
                    owner = owner.DeclaringType;
                }
            }
            return false;
        }

        private bool HasPrivateFieldAccess(MethodDef method, TypeDef declaringType)
        {
            if (!method.HasBody) return false;
            foreach (var instr in method.Body.Instructions)
            {
                if (instr.OpCode == DnOpCodes.Ldfld || instr.OpCode == DnOpCodes.Stfld ||
                    instr.OpCode == DnOpCodes.Ldsfld || instr.OpCode == DnOpCodes.Stsfld ||
                    instr.OpCode == DnOpCodes.Ldflda || instr.OpCode == DnOpCodes.Ldsflda)
                {
                    var fieldRef = instr.Operand as IField;
                    if (fieldRef == null) continue;
                    var fieldDef = fieldRef.ResolveFieldDef();
                    if (fieldDef == null) continue;
                    if (fieldDef.DeclaringType != declaringType) continue;
                    if (fieldDef.IsPrivate || fieldDef.IsFamily || fieldDef.IsFamilyAndAssembly)
                        return true;
                }

                if (instr.OpCode == DnOpCodes.Call || instr.OpCode == DnOpCodes.Callvirt ||
                    instr.OpCode == DnOpCodes.Ldftn || instr.OpCode == DnOpCodes.Ldvirtftn)
                {
                    var methodRef = instr.Operand as IMethod;
                    if (methodRef == null) continue;
                    var methodDef = methodRef.ResolveMethodDef();
                    if (methodDef == null) continue;
                    if (methodDef.DeclaringType != declaringType) continue;
                    if (methodDef.IsPrivate || methodDef.IsFamily || methodDef.IsFamilyAndAssembly)
                        return true;
                }

                if (instr.OpCode == DnOpCodes.Newobj)
                {
                    var methodRef = instr.Operand as IMethod;
                    if (methodRef == null) continue;
                    var declTR = methodRef.DeclaringType;
                    var nestedTypeDef = declTR == null ? null : declTR.ResolveTypeDef();
                    if (nestedTypeDef != null && nestedTypeDef.DeclaringType == declaringType)
                        return true;
                }
            }
            return false;
        }

        private bool ScatterMethod(ModuleDef module, MethodDef method)
        {
            var host = scatterHosts[rng.Next(scatterHosts.Count)];

            var cloneSig = CloneMethodSig(module, method.MethodSig);
            if (cloneSig == null) return false;

            var scattered = new MethodDefUser(engine.MakeName(),
                cloneSig,
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            scattered.Body = new CilBody();
            scattered.Body.InitLocals = method.Body.InitLocals;

            var localMap = new Dictionary<Local, Local>();
            foreach (var local in method.Body.Variables)
            {
                var nl = new Local(local.Type);
                scattered.Body.Variables.Add(nl);
                localMap[local] = nl;
            }

            var instrMap = new Dictionary<Instruction, Instruction>();
            foreach (var orig in method.Body.Instructions)
            {
                var clone = new Instruction(orig.OpCode);
                var asLocal = orig.Operand as Local;
                if (asLocal != null && localMap.ContainsKey(asLocal))
                    clone.Operand = localMap[asLocal];
                else
                    clone.Operand = orig.Operand;
                instrMap[orig] = clone;
                scattered.Body.Instructions.Add(clone);
            }

            foreach (var clone in scattered.Body.Instructions)
            {
                var asInstr = clone.Operand as Instruction;
                if (asInstr != null && instrMap.ContainsKey(asInstr))
                {
                    clone.Operand = instrMap[asInstr];
                }
                else
                {
                    var asInstrArr = clone.Operand as Instruction[];
                    if (asInstrArr != null)
                    {
                        var newTargets = new Instruction[asInstrArr.Length];
                        for (int t = 0; t < asInstrArr.Length; t++)
                        {
                            if (instrMap.ContainsKey(asInstrArr[t]))
                                newTargets[t] = instrMap[asInstrArr[t]];
                            else
                                newTargets[t] = asInstrArr[t];
                        }
                        clone.Operand = newTargets;
                    }
                }
            }

            foreach (var eh in method.Body.ExceptionHandlers)
            {
                var newEh = new ExceptionHandler(eh.HandlerType);
                if (eh.TryStart != null)
                {
                    if (!instrMap.ContainsKey(eh.TryStart)) return false;
                    newEh.TryStart = instrMap[eh.TryStart];
                }
                if (eh.TryEnd != null)
                {
                    if (!instrMap.ContainsKey(eh.TryEnd)) return false;
                    newEh.TryEnd = instrMap[eh.TryEnd];
                }
                if (eh.HandlerStart != null)
                {
                    if (!instrMap.ContainsKey(eh.HandlerStart)) return false;
                    newEh.HandlerStart = instrMap[eh.HandlerStart];
                }
                if (eh.HandlerEnd != null)
                {
                    if (!instrMap.ContainsKey(eh.HandlerEnd)) return false;
                    newEh.HandlerEnd = instrMap[eh.HandlerEnd];
                }
                if (eh.FilterStart != null)
                {
                    if (!instrMap.ContainsKey(eh.FilterStart)) return false;
                    newEh.FilterStart = instrMap[eh.FilterStart];
                }
                newEh.CatchType = eh.CatchType;
                scattered.Body.ExceptionHandlers.Add(newEh);
            }

            host.Methods.Add(scattered);
            engine.injectedMethods.Add(scattered);

            method.Body.Instructions.Clear();
            method.Body.ExceptionHandlers.Clear();
            method.Body.Variables.Clear();

            var il = method.Body.Instructions;
            for (int p = 0; p < method.Parameters.Count; p++)
            {
                switch (p)
                {
                    case 0: il.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                    case 1: il.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                    case 2: il.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                    case 3: il.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                    default: il.Add(Instruction.Create(DnOpCodes.Ldarg_S, method.Parameters[p])); break;
                }
            }
            il.Add(Instruction.Create(DnOpCodes.Call, scattered));
            il.Add(Instruction.Create(DnOpCodes.Ret));

            method.Body.SimplifyBranches();
            method.Body.OptimizeBranches();
            return true;
        }

        private MethodSig CloneMethodSig(ModuleDef module, MethodSig orig)
        {
            if (orig == null) return null;
            var paramTypes = new List<TypeSig>();
            foreach (var p in orig.Params)
                paramTypes.Add(p);
            return MethodSig.CreateStatic(orig.RetType, paramTypes.ToArray());
        }

        private void CreateBridgeMethods(ModuleDef module)
        {
            for (int b = 0; b < SCATTER_BRIDGE_COUNT; b++)
            {
                var host = scatterHosts[rng.Next(scatterHosts.Count)];
                var bridge = BuildBridgeMethod(module);
                host.Methods.Add(bridge);
                engine.injectedMethods.Add(bridge);
                bridgeMethods.Add(bridge);
            }
        }

        private void CreateFakeMethods(ModuleDef module)
        {
            for (int f = 0; f < SCATTER_FAKE_COUNT; f++)
            {
                var host = scatterHosts[rng.Next(scatterHosts.Count)];
                var fake = BuildFakeScatterMethod(module);
                host.Methods.Add(fake);
                engine.injectedMethods.Add(fake);
            }
        }

        private void InjectDecoyMethodNoise(ModuleDef module)
        {
            for (int i = 0; i < rng.Next(6, 12); i++)
            {
                var host = scatterHosts[rng.Next(scatterHosts.Count)];
                var decoy = BuildDecoyComputeMethod(module);
                host.Methods.Add(decoy);
                engine.injectedMethods.Add(decoy);
            }
        }

        private MethodDef BuildBridgeMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            for (int r = 0; r < rng.Next(4, 10); r++)
            {
                int op = rng.Next(0, 6);
                switch (op)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    case 1:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                    case 4:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildFakeScatterMethod(ModuleDef module)
        {
            int paramCount = rng.Next(1, 4);
            var paramTypes = new List<TypeSig>();
            for (int p = 0; p < paramCount; p++)
                paramTypes.Add(module.CorLibTypes.Int32);

            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, paramTypes.ToArray()),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            for (int r = 0; r < rng.Next(5, 12); r++)
            {
                int op = rng.Next(0, 5);
                switch (op)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 1:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }

        private MethodDef BuildDecoyComputeMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var il = method.Body.Instructions;

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));

            for (int r = 0; r < rng.Next(6, 14); r++)
            {
                int op = rng.Next(0, 8);
                switch (op)
                {
                    case 0:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    case 1:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.And));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    case 2:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                        break;
                    case 3:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                        il.Add(Instruction.Create(DnOpCodes.Sub));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                    case 4:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                        break;
                    case 5:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
                        il.Add(Instruction.Create(DnOpCodes.Shl));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Or));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_2));
                        break;
                    case 6:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                        il.Add(Instruction.Create(DnOpCodes.Not));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_1));
                        break;
                    default:
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                        il.Add(Instruction.Create(DnOpCodes.Add));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_3));
                        break;
                }
            }

            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            return method;
        }
    }
}

