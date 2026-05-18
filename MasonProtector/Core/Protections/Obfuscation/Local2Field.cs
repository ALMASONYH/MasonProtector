using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class Local2FieldProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal Local2FieldProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyLocal2Field(ModuleDef module)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (engine.controlFlowFlattenedMethods.Contains(method)) continue;
                    if (method.IsConstructor || method.IsStaticConstructor) continue;
                    if (method.Body.Variables.Count == 0) continue;
                    if (method.Body.Variables.Count > 20) continue;
                    if (method == module.EntryPoint) continue;
                    if (!method.IsStatic) continue;
                    try
                    {
                        ConvertLocalsToFields(module, method, type);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }
        }

        private void ConvertLocalsToFields(ModuleDef module, MethodDef method, TypeDef ownerType)
        {
            var localToFieldMap = new Dictionary<int, FieldDef>();
            var variables = method.Body.Variables;

            int maxConvert = Math.Min(variables.Count, 24);
            for (int v = 0; v < maxConvert; v++)
            {
                if (rng.Next(0, 3) == 0) continue;

                var local = variables[v];
                if (local.Type.FullName.StartsWith("System.Collections.")) continue;

                var et = local.Type.ElementType;
                if (et == ElementType.MVar || et == ElementType.Var ||
                    et == ElementType.ByRef || et == ElementType.Ptr ||
                    et == ElementType.Pinned) continue;

                var field = new FieldDefUser(engine.MakeName(),
                    new FieldSig(local.Type),
                    DnFieldAttributes.Private | DnFieldAttributes.Static);
                AttachThreadStatic(module, field);
                ownerType.Fields.Add(field);
                localToFieldMap[v] = field;
            }

            if (localToFieldMap.Count == 0) return;

            var il = method.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {
                int localIdx = GetLocalIndex(il[i]);
                if (localIdx < 0 || !localToFieldMap.ContainsKey(localIdx)) continue;

                var field = localToFieldMap[localIdx];

                if (IsLocalLoad(il[i]))
                {
                    il[i].OpCode = DnOpCodes.Ldsfld;
                    il[i].Operand = field;
                }
                else if (IsLocalStore(il[i]))
                {
                    il[i].OpCode = DnOpCodes.Stsfld;
                    il[i].Operand = field;
                }
                else if (IsLocalAddr(il[i]))
                {
                    il[i].OpCode = DnOpCodes.Ldsflda;
                    il[i].Operand = field;
                }
            }
        }

        private int GetLocalIndex(Instruction inst)
        {
            if (inst.OpCode == DnOpCodes.Ldloc_0 || inst.OpCode == DnOpCodes.Stloc_0) return 0;
            if (inst.OpCode == DnOpCodes.Ldloc_1 || inst.OpCode == DnOpCodes.Stloc_1) return 1;
            if (inst.OpCode == DnOpCodes.Ldloc_2 || inst.OpCode == DnOpCodes.Stloc_2) return 2;
            if (inst.OpCode == DnOpCodes.Ldloc_3 || inst.OpCode == DnOpCodes.Stloc_3) return 3;
            if (inst.Operand is Local)
                return ((Local)inst.Operand).Index;
            return -1;
        }

        private bool IsLocalLoad(Instruction inst)
        {
            return inst.OpCode == DnOpCodes.Ldloc || inst.OpCode == DnOpCodes.Ldloc_S ||
                   inst.OpCode == DnOpCodes.Ldloc_0 || inst.OpCode == DnOpCodes.Ldloc_1 ||
                   inst.OpCode == DnOpCodes.Ldloc_2 || inst.OpCode == DnOpCodes.Ldloc_3;
        }

        private bool IsLocalStore(Instruction inst)
        {
            return inst.OpCode == DnOpCodes.Stloc || inst.OpCode == DnOpCodes.Stloc_S ||
                   inst.OpCode == DnOpCodes.Stloc_0 || inst.OpCode == DnOpCodes.Stloc_1 ||
                   inst.OpCode == DnOpCodes.Stloc_2 || inst.OpCode == DnOpCodes.Stloc_3;
        }

        private bool IsLocalAddr(Instruction inst)
        {
            return inst.OpCode == DnOpCodes.Ldloca || inst.OpCode == DnOpCodes.Ldloca_S;
        }

        private void AttachThreadStatic(ModuleDef module, FieldDef field)
        {
            try
            {
                Importer importer = new Importer(module);
                IMethod ctor = importer.Import(typeof(System.ThreadStaticAttribute).GetConstructor(Type.EmptyTypes));
                if (ctor == null) return;
                CustomAttribute ca = new CustomAttribute((ICustomAttributeType)ctor);
                field.CustomAttributes.Add(ca);
            }
            catch { }
        }
    }
}

