using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace MasonProtector.Core
{
    internal class TypeCloner
    {
        private readonly ModuleDef srcModule;
        private readonly ModuleDef dstModule;
        private readonly Importer importer;

        private readonly Dictionary<TypeDef, TypeDef> typeMap =
            new Dictionary<TypeDef, TypeDef>();
        private readonly Dictionary<FieldDef, FieldDef> fieldMap =
            new Dictionary<FieldDef, FieldDef>();
        private readonly Dictionary<MethodDef, MethodDef> methodMap =
            new Dictionary<MethodDef, MethodDef>();

        internal TypeCloner(ModuleDef src, ModuleDef dst)
        {
            srcModule = src;
            dstModule = dst;
            importer = new Importer(dst);
        }

        internal TypeDef CloneType(TypeDef src, string newNamespace, string newName)
        {
            TypeDef dst = ShellType(src, newNamespace, newName);
            dstModule.Types.Add(dst);
            ShellNestedTypesRecursive(src, dst);

            ShellFieldsRecursive(src, dst);

            ShellMethodsRecursive(src, dst);

            CloneBodiesRecursive(src);

            return dst;
        }

        private void ShellNestedTypesRecursive(TypeDef src, TypeDef dst)
        {
            foreach (TypeDef nested in src.NestedTypes)
            {
                TypeDef dstNested = ShellType(nested, "", nested.Name);
                dst.NestedTypes.Add(dstNested);
                ShellNestedTypesRecursive(nested, dstNested);
            }
        }

        private void ShellFieldsRecursive(TypeDef src, TypeDef dst)
        {
            foreach (FieldDef sf in src.Fields)
            {
                FieldSig newSig;
                if (sf.FieldSig != null && sf.FieldSig.Type != null)
                    newSig = new FieldSig(RemapImport(sf.FieldSig.Type));
                else
                    newSig = new FieldSig(dstModule.CorLibTypes.Object);

                FieldDefUser df = new FieldDefUser(sf.Name, newSig, sf.Attributes);
                if (sf.HasFieldRVA && sf.InitialValue != null)
                {
                    df.InitialValue = (byte[])sf.InitialValue.Clone();
                    df.HasFieldRVA = true;
                }
                dst.Fields.Add(df);
                fieldMap[sf] = df;
            }
            foreach (TypeDef nested in src.NestedTypes)
                ShellFieldsRecursive(nested, typeMap[nested]);
        }

        private void ShellMethodsRecursive(TypeDef src, TypeDef dst)
        {
            foreach (MethodDef sm in src.Methods)
            {
                MethodSig newMSig = ImportMethodSig(sm.MethodSig);
                MethodDefUser dm = new MethodDefUser(sm.Name, newMSig,
                    sm.ImplAttributes, sm.Attributes);

                foreach (ParamDef sp in sm.ParamDefs)
                {
                    ParamDefUser dp = new ParamDefUser(sp.Name, sp.Sequence,
                        sp.Attributes);
                    dm.ParamDefs.Add(dp);
                }

                dst.Methods.Add(dm);
                methodMap[sm] = dm;
            }
            foreach (TypeDef nested in src.NestedTypes)
                ShellMethodsRecursive(nested, typeMap[nested]);
        }

        private void CloneBodiesRecursive(TypeDef src)
        {
            foreach (MethodDef sm in src.Methods)
            {
                if (sm.HasBody)
                    CloneBody(sm, methodMap[sm]);
            }
            foreach (TypeDef nested in src.NestedTypes)
                CloneBodiesRecursive(nested);
        }

        private TypeSig RemapImport(TypeSig sig)
        {
            if (sig == null) return null;

            if (sig is CorLibTypeSig)
                return importer.Import(sig);

            if (sig is GenericInstSig)
            {
                GenericInstSig gi = (GenericInstSig)sig;
                ClassOrValueTypeSig genType =
                    (ClassOrValueTypeSig)RemapImport(gi.GenericType);
                List<TypeSig> args = new List<TypeSig>(gi.GenericArguments.Count);
                foreach (TypeSig a in gi.GenericArguments) args.Add(RemapImport(a));
                return new GenericInstSig(genType, args);
            }
            if (sig is SZArraySig)
                return new SZArraySig(RemapImport(sig.Next));
            if (sig is ArraySig)
            {
                ArraySig a = (ArraySig)sig;
                return new ArraySig(RemapImport(sig.Next), a.Rank, a.Sizes, a.LowerBounds);
            }
            if (sig is ByRefSig)
                return new ByRefSig(RemapImport(sig.Next));
            if (sig is PtrSig)
                return new PtrSig(RemapImport(sig.Next));
            if (sig is PinnedSig)
                return new PinnedSig(RemapImport(sig.Next));
            if (sig is ClassSig)
            {
                ITypeDefOrRef tdr = ((ClassSig)sig).TypeDefOrRef;
                TypeDef td = tdr as TypeDef;
                if (td != null && typeMap.ContainsKey(td))
                    return new ClassSig(typeMap[td]);
                return importer.Import(sig);
            }
            if (sig is ValueTypeSig)
            {
                ITypeDefOrRef tdr = ((ValueTypeSig)sig).TypeDefOrRef;
                TypeDef td = tdr as TypeDef;
                if (td != null && typeMap.ContainsKey(td))
                    return new ValueTypeSig(typeMap[td]);
                return importer.Import(sig);
            }
            return importer.Import(sig);
        }

        private ITypeDefOrRef RemapImport(ITypeDefOrRef tdr)
        {
            if (tdr == null) return null;
            TypeDef td = tdr as TypeDef;
            if (td != null && typeMap.ContainsKey(td))
                return typeMap[td];
            return importer.Import(tdr);
        }

        private TypeDef ShellType(TypeDef src, string newNamespace, string newName)
        {
            ITypeDefOrRef baseImported = src.BaseType != null
                ? RemapImport(src.BaseType)
                : null;
            TypeDefUser dst = new TypeDefUser(newNamespace ?? "",
                newName ?? src.Name, baseImported);
            dst.Attributes = src.Attributes;
            dst.ClassLayout = src.ClassLayout != null
                ? new ClassLayoutUser(src.ClassLayout.PackingSize, src.ClassLayout.ClassSize)
                : null;
            foreach (InterfaceImpl ii in src.Interfaces)
            {
                ITypeDefOrRef imp = RemapImport(ii.Interface);
                dst.Interfaces.Add(new InterfaceImplUser(imp));
            }
            typeMap[src] = dst;
            return dst;
        }

        private MethodSig ImportMethodSig(MethodSig sig)
        {
            if (sig == null) return MethodSig.CreateStatic(dstModule.CorLibTypes.Void);
            TypeSig retImported = RemapImport(sig.RetType);
            TypeSig[] paramImported = new TypeSig[sig.Params.Count];
            for (int i = 0; i < sig.Params.Count; i++)
                paramImported[i] = RemapImport(sig.Params[i]);

            MethodSig newSig;
            if (sig.HasThis)
            {
                if (paramImported.Length == 0)
                    newSig = MethodSig.CreateInstance(retImported);
                else
                    newSig = MethodSig.CreateInstance(retImported, paramImported);
            }
            else
            {
                if (paramImported.Length == 0)
                    newSig = MethodSig.CreateStatic(retImported);
                else
                    newSig = MethodSig.CreateStatic(retImported, paramImported);
            }
            newSig.CallingConvention = sig.CallingConvention;
            return newSig;
        }

        private void CloneBody(MethodDef src, MethodDef dst)
        {
            CilBody sb = src.Body;
            CilBody db = new CilBody();
            db.MaxStack = sb.MaxStack;
            db.InitLocals = sb.InitLocals;
            db.KeepOldMaxStack = sb.KeepOldMaxStack;

            Dictionary<Local, Local> localMap = new Dictionary<Local, Local>();
            foreach (Local sl in sb.Variables)
            {
                TypeSig importedTs = sl.Type != null
                    ? RemapImport(sl.Type)
                    : dstModule.CorLibTypes.Object;
                Local dl = new Local(importedTs, sl.Name);
                db.Variables.Add(dl);
                localMap[sl] = dl;
            }

            Dictionary<Parameter, Parameter> paramMap = new Dictionary<Parameter, Parameter>();
            int n = Math.Min(src.Parameters.Count, dst.Parameters.Count);
            for (int i = 0; i < n; i++)
                paramMap[src.Parameters[i]] = dst.Parameters[i];

            Dictionary<Instruction, Instruction> insMap =
                new Dictionary<Instruction, Instruction>();
            foreach (Instruction si in sb.Instructions)
            {
                Instruction di = new Instruction(si.OpCode);
                di.Offset = si.Offset;
                insMap[si] = di;
            }

            foreach (Instruction si in sb.Instructions)
            {
                Instruction di = insMap[si];
                di.Operand = TranslateOperand(si.Operand, localMap, paramMap, insMap);
            }

            foreach (Instruction si in sb.Instructions)
                db.Instructions.Add(insMap[si]);

            foreach (ExceptionHandler seh in sb.ExceptionHandlers)
            {
                ExceptionHandler deh = new ExceptionHandler(seh.HandlerType);
                if (seh.TryStart != null      && insMap.ContainsKey(seh.TryStart))      deh.TryStart      = insMap[seh.TryStart];
                if (seh.TryEnd != null        && insMap.ContainsKey(seh.TryEnd))        deh.TryEnd        = insMap[seh.TryEnd];
                if (seh.HandlerStart != null  && insMap.ContainsKey(seh.HandlerStart))  deh.HandlerStart  = insMap[seh.HandlerStart];
                if (seh.HandlerEnd != null    && insMap.ContainsKey(seh.HandlerEnd))    deh.HandlerEnd    = insMap[seh.HandlerEnd];
                if (seh.FilterStart != null   && insMap.ContainsKey(seh.FilterStart))   deh.FilterStart   = insMap[seh.FilterStart];
                if (seh.CatchType != null)
                    deh.CatchType = RemapImport(seh.CatchType);
                db.ExceptionHandlers.Add(deh);
            }

            dst.Body = db;
        }

        private object TranslateOperand(object op,
            Dictionary<Local, Local> localMap,
            Dictionary<Parameter, Parameter> paramMap,
            Dictionary<Instruction, Instruction> insMap)
        {
            if (op == null) return null;

            Instruction insOp = op as Instruction;
            if (insOp != null)
            {
                Instruction tgt;
                return insMap.TryGetValue(insOp, out tgt) ? tgt : insOp;
            }
            Instruction[] insArr = op as Instruction[];
            if (insArr != null)
            {
                Instruction[] dstArr = new Instruction[insArr.Length];
                for (int i = 0; i < insArr.Length; i++)
                {
                    Instruction tgt;
                    dstArr[i] = insMap.TryGetValue(insArr[i], out tgt) ? tgt : insArr[i];
                }
                return dstArr;
            }

            Local lOp = op as Local;
            if (lOp != null)
            {
                Local mapped;
                return localMap.TryGetValue(lOp, out mapped) ? mapped : lOp;
            }
            Parameter pOp = op as Parameter;
            if (pOp != null)
            {
                Parameter mapped;
                return paramMap.TryGetValue(pOp, out mapped) ? mapped : pOp;
            }

            if (op is string) return op;

            if (op is sbyte || op is byte ||
                op is short || op is ushort ||
                op is int   || op is uint  ||
                op is long  || op is ulong ||
                op is float || op is double)
                return op;

            IMethod mOp = op as IMethod;
            if (mOp != null)
            {
                MethodDef md = mOp as MethodDef;
                if (md != null && methodMap.ContainsKey(md))
                    return methodMap[md];
                return importer.Import(mOp);
            }

            IField fOp = op as IField;
            if (fOp != null)
            {
                FieldDef fd = fOp as FieldDef;
                if (fd != null && fieldMap.ContainsKey(fd))
                    return fieldMap[fd];
                return importer.Import(fOp);
            }

            ITypeDefOrRef tOp = op as ITypeDefOrRef;
            if (tOp != null)
            {
                TypeDef td = tOp as TypeDef;
                if (td != null && typeMap.ContainsKey(td))
                    return typeMap[td];
                return importer.Import(tOp);
            }

            MethodSig msOp = op as MethodSig;
            if (msOp != null)
                return ImportMethodSig(msOp);

            return op;
        }

    }
}

