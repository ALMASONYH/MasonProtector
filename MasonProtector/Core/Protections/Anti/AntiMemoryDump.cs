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
    internal class AntiMemoryDumpProtection
    {
        private Obfuscation engine;
        private Random rng;

        private static readonly string[] securityAttrNames = new string[]
        {
            "MemoryProtectionAttribute", "HeapGuardAttribute", "DumpShieldAttribute",
            "StackIntegrityAttribute", "SecureMemoryAttribute", "AntiDumpAttribute",
            "RuntimeGuardAttribute", "MemoryFenceAttribute", "PageProtectAttribute",
            "VirtualGuardAttribute", "HeapValidatorAttribute", "StackSentinelAttribute",
            "MemoryWatcherAttribute", "ProcessGuardAttribute", "ThreadSafetyAttribute"
        };

        private static readonly string[] phantomMethodNames = new string[]
        {
            "ValidateHeapIntegrity", "CheckMemoryPages", "VerifyStackGuard",
            "ScanProcessMemory", "EnforcePageProtection", "DetectDumpAttempt",
            "MonitorVirtualMemory", "ValidateModuleHeaders", "CheckPEIntegrity",
            "VerifyImageBase", "ScanForBreakpoints", "EnforceMemoryPolicy",
            "DetectHollowing", "MonitorThreadStack", "ValidateCodeSection",
            "CheckImportTable", "VerifyExportDirectory", "ScanRelocationTable",
            "EnforceDataIntegrity", "DetectPatchAttempt", "MonitorBaseAddress",
            "ValidateEntryPoint", "CheckResourceSection", "VerifyDebugDirectory"
        };

        private static readonly string[] decoyTypeNames = new string[]
        {
            "MemoryGuardEngine", "HeapProtector", "DumpPrevention",
            "StackValidator", "PageMonitor", "VirtualMemoryFence",
            "ProcessIntegrityChecker", "ThreadStackGuard", "ModuleHeaderValidator",
            "CodeSectionMonitor", "ImportTableWatcher", "RelocationGuard"
        };

        internal AntiMemoryDumpProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiMemoryDump(ModuleDef module, TypeDef modType)
        {
            InjectSecurityAttributes(module);
            List<TypeDefUser> hostTypes = CreateHostTypes(module);
            foreach (TypeDefUser host in hostTypes)
            {
                PopulateFields(module, host);
                PopulateMethods(module, host);
                InjectNestedTypes(module, host, 0);
                module.Types.Add(host);
                engine.injectedTypes.Add(host);
            }
            InjectPhantomMethods(module, modType);
            InjectTrapHandlerTypes(module);
        }

        private void InjectSecurityAttributes(ModuleDef module)
        {
            ITypeDefOrRef attrBase = module.Import(typeof(Attribute));
            List<string> chosen = new List<string>();
            foreach (string name in securityAttrNames)
            {
                if (rng.Next(0, 3) == 0) continue;
                chosen.Add(name);
            }
            if (chosen.Count < 5)
            {
                for (int i = 0; i < securityAttrNames.Length && chosen.Count < 5; i++)
                {
                    if (!chosen.Contains(securityAttrNames[i]))
                        chosen.Add(securityAttrNames[i]);
                }
            }

            foreach (string attrName in chosen)
            {
                var attrType = new TypeDefUser("System.Security", attrName, attrBase);
                attrType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed |
                    DnTypeAttributes.BeforeFieldInit;

                var ctor = new MethodDefUser(".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                    DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
                ctor.Body = new CilBody();
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
                var baseCtorRef = new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void), attrBase);
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, baseCtorRef));
                ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                attrType.Methods.Add(ctor);
                engine.injectedMethods.Add(ctor);

                for (int f = 0; f < rng.Next(1, 4); f++)
                {
                    TypeSig ft;
                    switch (rng.Next(0, 3))
                    {
                        case 0: ft = module.CorLibTypes.Int32; break;
                        case 1: ft = module.CorLibTypes.Boolean; break;
                        default: ft = module.CorLibTypes.String; break;
                    }
                    attrType.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(6, 12)),
                        new FieldSig(ft),
                        DnFieldAttributes.Private));
                }

                module.Types.Add(attrType);
                engine.injectedTypes.Add(attrType);

                var ca = new CustomAttribute(ctor);
                module.CustomAttributes.Add(ca);
                if (module.Assembly != null && rng.Next(0, 2) == 0)
                {
                    module.Assembly.CustomAttributes.Add(new CustomAttribute(ctor));
                }
            }
        }

        private List<TypeDefUser> CreateHostTypes(ModuleDef module)
        {
            int count = rng.Next(12, 24);
            List<TypeDefUser> result = new List<TypeDefUser>();
            for (int i = 0; i < count; i++)
            {
                string ns;
                switch (rng.Next(0, 5))
                {
                    case 0: ns = "System.Runtime.Protection"; break;
                    case 1: ns = "System.Security.Memory"; break;
                    case 2: ns = "System.Diagnostics.Guard"; break;
                    case 3: ns = "Microsoft.Runtime.Integrity"; break;
                    default: ns = ""; break;
                }

                string typeName;
                if (i < decoyTypeNames.Length)
                {
                    typeName = decoyTypeNames[i] + engine.MakeName(rng.Next(4, 8));
                }
                else
                {
                    typeName = engine.MakeName(rng.Next(10, 18));
                }

                var host = new TypeDefUser(ns, typeName,
                    module.CorLibTypes.Object.TypeDefOrRef);
                host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                result.Add(host);
            }
            return result;
        }

        private void PopulateFields(ModuleDef module, TypeDefUser host)
        {
            int fieldCount = rng.Next(12, 24);
            for (int i = 0; i < fieldCount; i++)
            {
                TypeSig fieldType;
                switch (rng.Next(0, 8))
                {
                    case 0: fieldType = module.CorLibTypes.Int32; break;
                    case 1: fieldType = module.CorLibTypes.Int64; break;
                    case 2: fieldType = module.CorLibTypes.Boolean; break;
                    case 3: fieldType = new SZArraySig(module.CorLibTypes.Int32); break;
                    case 4: fieldType = new SZArraySig(module.CorLibTypes.Byte); break;
                    case 5: fieldType = module.CorLibTypes.IntPtr; break;
                    case 6: fieldType = module.CorLibTypes.UIntPtr; break;
                    default: fieldType = new SZArraySig(module.CorLibTypes.Int64); break;
                }

                DnFieldAttributes fa = DnFieldAttributes.Private | DnFieldAttributes.Static;
                if (rng.Next(0, 4) == 0)
                    fa = DnFieldAttributes.Assembly | DnFieldAttributes.Static;

                host.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(6, 14)),
                    new FieldSig(fieldType), fa));
            }
        }

        private void PopulateMethods(ModuleDef module, TypeDefUser host)
        {
            int methodCount = rng.Next(4, 9);
            for (int i = 0; i < methodCount; i++)
            {
                MethodDef md;
                switch (rng.Next(0, 4))
                {
                    case 0:
                        md = BuildArithmeticTrapMethod(module);
                        break;
                    case 1:
                        md = BuildBranchingTrapMethod(module);
                        break;
                    case 2:
                        md = BuildExceptionTrapMethod(module);
                        break;
                    default:
                        md = BuildBitwiseTrapMethod(module);
                        break;
                }
                host.Methods.Add(md);
                engine.injectedMethods.Add(md);
            }
        }

        private MethodDef BuildArithmeticTrapMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(rng.Next(8, 16)),
                MethodSig.CreateStatic(module.CorLibTypes.Int64,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int64));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int64));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

            var il = method.Body.Instructions;
            var retLabel = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Mul));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)rng.Next() * (long)rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(retLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildBranchingTrapMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(rng.Next(8, 16)),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Boolean),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));

            var il = method.Body.Instructions;
            var endLabel = Instruction.Create(DnOpCodes.Ldloc_0);
            var branchA = Instruction.Create(DnOpCodes.Ldarg_0);
            var branchB = Instruction.Create(DnOpCodes.Ldloc_1);
            var branchC = Instruction.Create(DnOpCodes.Ldloc_2);
            var loopHead = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 100)));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(50, 200)));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Brtrue, branchA));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Bgt, branchB));
            il.Add(Instruction.Create(DnOpCodes.Br, branchC));

            il.Add(branchA);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[4]));
            il.Add(loopHead);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(3, 8)));
            il.Add(Instruction.Create(DnOpCodes.Bge, endLabel));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[4]));
            il.Add(Instruction.Create(DnOpCodes.Br, loopHead));

            il.Add(branchB);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, endLabel));

            il.Add(branchC);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(endLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private MethodDef BuildExceptionTrapMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(rng.Next(8, 16)),
                MethodSig.CreateStatic(module.CorLibTypes.Void,
                    module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int64));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Object));

            var il = method.Body.Instructions;

            var tryStart = Instruction.Create(DnOpCodes.Ldarg_0);
            var tryEnd = Instruction.Create(DnOpCodes.Nop);
            var catchStart = Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[4]);
            var catchEnd = Instruction.Create(DnOpCodes.Nop);
            var finallyStart = Instruction.Create(DnOpCodes.Ldloc_0);
            var finallyEnd = Instruction.Create(DnOpCodes.Endfinally);
            var afterAll = Instruction.Create(DnOpCodes.Ret);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)rng.Next() << 16));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterAll));
            il.Add(tryEnd);

            il.Add(catchStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Leave, afterAll));
            il.Add(catchEnd);

            il.Add(finallyStart);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(finallyEnd);

            il.Add(afterAll);

            var exBody = method.Body;
            exBody.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = catchStart,
                HandlerStart = catchStart,
                HandlerEnd = finallyStart,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });
            exBody.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            {
                TryStart = tryStart,
                TryEnd = finallyStart,
                HandlerStart = finallyStart,
                HandlerEnd = afterAll
            });

            return method;
        }

        private MethodDef BuildBitwiseTrapMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(rng.Next(8, 16)),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

            var il = method.Body.Instructions;
            var skipLabel = Instruction.Create(DnOpCodes.Ldloc_3);
            var endLabel = Instruction.Create(DnOpCodes.Ldloc_0);

            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_3));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 24)));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Bgt, skipLabel));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Br, endLabel));
            il.Add(skipLabel);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_2));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 16)));
            il.Add(Instruction.Create(DnOpCodes.Shr_Un));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_2));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(endLabel);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            return method;
        }

        private void InjectNestedTypes(ModuleDef module, TypeDefUser parent, int depth)
        {
            if (depth >= 3 + rng.Next(0, 2))
                return;

            int nestedCount = rng.Next(1, 3);
            for (int n = 0; n < nestedCount; n++)
            {
                string nestedName;
                switch (rng.Next(0, 4))
                {
                    case 0: nestedName = "GuardContext" + engine.MakeName(rng.Next(3, 6)); break;
                    case 1: nestedName = "ProtectionState" + engine.MakeName(rng.Next(3, 6)); break;
                    case 2: nestedName = "MemoryRegion" + engine.MakeName(rng.Next(3, 6)); break;
                    default: nestedName = engine.MakeName(rng.Next(8, 14)); break;
                }

                var nested = new TypeDefUser("", nestedName,
                    module.CorLibTypes.Object.TypeDefOrRef);
                nested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

                int fCount = rng.Next(2, 6);
                for (int f = 0; f < fCount; f++)
                {
                    TypeSig ft;
                    switch (rng.Next(0, 6))
                    {
                        case 0: ft = module.CorLibTypes.Int32; break;
                        case 1: ft = module.CorLibTypes.Int64; break;
                        case 2: ft = module.CorLibTypes.Boolean; break;
                        case 3: ft = new SZArraySig(module.CorLibTypes.Byte); break;
                        case 4: ft = module.CorLibTypes.IntPtr; break;
                        default: ft = module.CorLibTypes.UIntPtr; break;
                    }
                    nested.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(5, 12)),
                        new FieldSig(ft),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                int mCount = rng.Next(1, 4);
                for (int m = 0; m < mCount; m++)
                {
                    MethodDef nestedMethod;
                    if (rng.Next(0, 2) == 0)
                    {
                        nestedMethod = BuildArithmeticTrapMethod(module);
                    }
                    else
                    {
                        nestedMethod = BuildBitwiseTrapMethod(module);
                    }
                    nested.Methods.Add(nestedMethod);
                    engine.injectedMethods.Add(nestedMethod);
                }

                parent.NestedTypes.Add(nested);
                engine.injectedTypes.Add(nested);

                InjectNestedTypes(module, nested, depth + 1);
            }
        }

        private void InjectPhantomMethods(ModuleDef module, TypeDef modType)
        {
            List<string> usedNames = new List<string>();
            int phantomCount = rng.Next(6, 12);
            for (int i = 0; i < phantomCount; i++)
            {
                string baseName;
                if (i < phantomMethodNames.Length)
                {
                    baseName = phantomMethodNames[i];
                }
                else
                {
                    baseName = phantomMethodNames[rng.Next(0, phantomMethodNames.Length)];
                }
                string finalName = baseName + engine.MakeName(rng.Next(3, 6));
                if (usedNames.Contains(finalName))
                {
                    finalName = finalName + engine.MakeName(rng.Next(2, 4));
                }
                usedNames.Add(finalName);

                TypeSig retType;
                switch (rng.Next(0, 4))
                {
                    case 0: retType = module.CorLibTypes.Boolean; break;
                    case 1: retType = module.CorLibTypes.Int32; break;
                    case 2: retType = module.CorLibTypes.Void; break;
                    default: retType = module.CorLibTypes.Int64; break;
                }

                int paramC = rng.Next(0, 4);
                TypeSig[] pars = new TypeSig[paramC];
                for (int p = 0; p < paramC; p++)
                {
                    switch (rng.Next(0, 5))
                    {
                        case 0: pars[p] = module.CorLibTypes.Int32; break;
                        case 1: pars[p] = module.CorLibTypes.IntPtr; break;
                        case 2: pars[p] = module.CorLibTypes.Boolean; break;
                        case 3: pars[p] = module.CorLibTypes.Int64; break;
                        default: pars[p] = module.CorLibTypes.UInt32; break;
                    }
                }

                var phantomSig = MethodSig.CreateStatic(retType, pars);
                var phantom = new MethodDefUser(finalName, phantomSig,
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

                phantom.Body = new CilBody();
                phantom.Body.InitLocals = true;
                phantom.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
                phantom.Body.Variables.Add(new Local(module.CorLibTypes.Int64));
                phantom.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));

                var pil = phantom.Body.Instructions;
                var tryStart = Instruction.Create(DnOpCodes.Ldc_I4, rng.Next());
                var catchStart = Instruction.Create(DnOpCodes.Pop);
                var afterCatch = Instruction.Create(DnOpCodes.Nop);

                pil.Add(tryStart);
                pil.Add(Instruction.Create(DnOpCodes.Stloc_0));
                pil.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                pil.Add(Instruction.Create(DnOpCodes.Conv_I8));
                pil.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)rng.Next() * 3L));
                pil.Add(Instruction.Create(DnOpCodes.Xor));
                pil.Add(Instruction.Create(DnOpCodes.Stloc_1));
                pil.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                pil.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 20)));
                pil.Add(Instruction.Create(DnOpCodes.Shl));
                pil.Add(Instruction.Create(DnOpCodes.Not));
                pil.Add(Instruction.Create(DnOpCodes.Stloc_0));
                pil.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

                pil.Add(catchStart);
                pil.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                pil.Add(Instruction.Create(DnOpCodes.Stloc_2));
                pil.Add(Instruction.Create(DnOpCodes.Leave, afterCatch));

                pil.Add(afterCatch);

                if (retType.FullName == "System.Void")
                {
                    pil.Add(Instruction.Create(DnOpCodes.Ret));
                }
                else if (retType.FullName == "System.Boolean")
                {
                    pil.Add(Instruction.Create(DnOpCodes.Ldloc_2));
                    pil.Add(Instruction.Create(DnOpCodes.Ret));
                }
                else if (retType.FullName == "System.Int64")
                {
                    pil.Add(Instruction.Create(DnOpCodes.Ldloc_1));
                    pil.Add(Instruction.Create(DnOpCodes.Ret));
                }
                else
                {
                    pil.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    pil.Add(Instruction.Create(DnOpCodes.Ret));
                }

                phantom.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                {
                    TryStart = tryStart,
                    TryEnd = catchStart,
                    HandlerStart = catchStart,
                    HandlerEnd = afterCatch,
                    CatchType = module.CorLibTypes.Object.TypeDefOrRef
                });

                modType.Methods.Add(phantom);
                engine.injectedMethods.Add(phantom);
            }
        }

        private void InjectTrapHandlerTypes(ModuleDef module)
        {
            int trapCount = rng.Next(2, 5);
            for (int t = 0; t < trapCount; t++)
            {
                string trapName;
                switch (rng.Next(0, 5))
                {
                    case 0: trapName = "DumpInterceptor" + engine.MakeName(rng.Next(4, 8)); break;
                    case 1: trapName = "MemoryValidator" + engine.MakeName(rng.Next(4, 8)); break;
                    case 2: trapName = "HeapSentinel" + engine.MakeName(rng.Next(4, 8)); break;
                    case 3: trapName = "PageGuard" + engine.MakeName(rng.Next(4, 8)); break;
                    default: trapName = "IntegrityMonitor" + engine.MakeName(rng.Next(4, 8)); break;
                }

                var trapType = new TypeDefUser("System.Runtime.InteropServices", trapName,
                    module.CorLibTypes.Object.TypeDefOrRef);
                trapType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;

                for (int f = 0; f < rng.Next(3, 7); f++)
                {
                    TypeSig ft;
                    switch (rng.Next(0, 5))
                    {
                        case 0: ft = module.CorLibTypes.IntPtr; break;
                        case 1: ft = module.CorLibTypes.UIntPtr; break;
                        case 2: ft = new SZArraySig(module.CorLibTypes.Byte); break;
                        case 3: ft = module.CorLibTypes.Int64; break;
                        default: ft = module.CorLibTypes.Int32; break;
                    }
                    trapType.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(6, 12)),
                        new FieldSig(ft),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                for (int m = 0; m < rng.Next(3, 6); m++)
                {
                    var tm = BuildTrapHandlerMethod(module);
                    trapType.Methods.Add(tm);
                    engine.injectedMethods.Add(tm);
                }

                var innerNested = new TypeDefUser("", "State" + engine.MakeName(rng.Next(4, 8)),
                    module.CorLibTypes.Object.TypeDefOrRef);
                innerNested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                innerNested.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(6, 10)),
                    new FieldSig(module.CorLibTypes.Int32),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
                innerNested.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(6, 10)),
                    new FieldSig(module.CorLibTypes.Boolean),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
                innerNested.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(6, 10)),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Int64)),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));

                var deepNested = new TypeDefUser("", "Ctx" + engine.MakeName(rng.Next(3, 6)),
                    module.CorLibTypes.Object.TypeDefOrRef);
                deepNested.Attributes = DnTypeAttributes.NestedPrivate | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
                deepNested.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(5, 10)),
                    new FieldSig(module.CorLibTypes.IntPtr),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
                deepNested.Fields.Add(new FieldDefUser(engine.MakeName(rng.Next(5, 10)),
                    new FieldSig(module.CorLibTypes.UIntPtr),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
                innerNested.NestedTypes.Add(deepNested);
                engine.injectedTypes.Add(deepNested);

                trapType.NestedTypes.Add(innerNested);
                engine.injectedTypes.Add(innerNested);

                module.Types.Add(trapType);
                engine.injectedTypes.Add(trapType);
            }
        }

        private MethodDef BuildTrapHandlerMethod(ModuleDef module)
        {
            var method = new MethodDefUser(engine.MakeName(rng.Next(8, 16)),
                MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            method.Body = new CilBody();
            method.Body.InitLocals = true;
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int64));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Boolean));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            method.Body.Variables.Add(new Local(module.CorLibTypes.Object));

            var il = method.Body.Instructions;
            var tryStart = Instruction.Create(DnOpCodes.Ldarg_0);
            var catchStart = Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[5]);
            var finallyStart = Instruction.Create(DnOpCodes.Ldloc, method.Body.Variables[4]);
            var finallyEnd = Instruction.Create(DnOpCodes.Endfinally);
            var retBlock = Instruction.Create(DnOpCodes.Ldloc_0);
            var midBranch = Instruction.Create(DnOpCodes.Ldloc_1);

            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[4]));

            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_1));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_1));
            il.Add(Instruction.Create(DnOpCodes.And));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next(1, 12)));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Conv_I8));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I8, (long)rng.Next() << 8));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Stloc_2));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(DnOpCodes.Blt, midBranch));
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldarg_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, retBlock));
            il.Add(midBranch);
            il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Leave, retBlock));

            il.Add(catchStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
            il.Add(Instruction.Create(DnOpCodes.Stloc_0));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Stloc_3));
            il.Add(Instruction.Create(DnOpCodes.Leave, retBlock));

            il.Add(finallyStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Stloc, method.Body.Variables[4]));
            il.Add(finallyEnd);

            il.Add(retBlock);
            il.Add(Instruction.Create(DnOpCodes.Ret));

            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = catchStart,
                HandlerStart = catchStart,
                HandlerEnd = finallyStart,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });
            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            {
                TryStart = tryStart,
                TryEnd = finallyStart,
                HandlerStart = finallyStart,
                HandlerEnd = retBlock
            });

            return method;
        }
    }
}

