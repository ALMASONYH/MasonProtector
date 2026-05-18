using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class CalliConversionProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal CalliConversionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyCalliConversion(ModuleDef module)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;
                foreach (MethodDef method in type.Methods)
                {
                    if (!engine.CanProcessMethod(method)) continue;
                    if (engine.MethodHasAsyncOrIteratorAttribute(method)) continue;
                    try
                    {
                        ConvertCallsToCalli(module, method);
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                    catch { }
                }
            }
        }

        private void ConvertCallsToCalli(ModuleDef module, MethodDef method)
        {
            if (method.Body.HasExceptionHandlers) return;
            var il = method.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode != DnOpCodes.Call) continue;

                var target = il[i].Operand as IMethod;
                if (target == null) continue;
                if (target is MethodDef) continue;
                if (engine.IsCompilerInfrastructureCall(target)) continue;

                var targetSig = target.MethodSig;
                if (targetSig == null) continue;
                if (targetSig.HasThis) continue;
                if (targetSig.GenParamCount > 0) continue;
                if (targetSig.Params.Count > 4) continue;

                var cconv = targetSig.CallingConvention & dnlib.DotNet.CallingConvention.Mask;
                if (cconv != dnlib.DotNet.CallingConvention.Default) continue;

                bool hasComplexParam = false;
                foreach (var p in targetSig.Params)
                {
                    if (p == null) { hasComplexParam = true; break; }
                    if (p.IsByRef || p.IsPointer) { hasComplexParam = true; break; }
                }
                if (hasComplexParam) continue;
                if (targetSig.RetType == null) continue;

                if (rng.Next(0, 2) != 0) continue;

                var importer = new Importer(module);
                var importedRet = importer.Import(targetSig.RetType);
                var importedParams = new TypeSig[targetSig.Params.Count];
                for (int pi = 0; pi < targetSig.Params.Count; pi++)
                    importedParams[pi] = importer.Import(targetSig.Params[pi]);

                var calliSig = MethodSig.CreateStatic(importedRet, importedParams);

                il[i].OpCode = DnOpCodes.Ldftn;
                il[i].Operand = target;
                il.Insert(i + 1, Instruction.Create(DnOpCodes.Calli, calliSig));
                i++;
            }
        }
    }
}

