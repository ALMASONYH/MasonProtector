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
    internal class TokenConfusionProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal TokenConfusionProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyTokenConfusion(ModuleDef module)
        {
            InjectDummyInterfaces(module);
            InjectPInvokeDecoys(module);
            InjectDummyGenericTypes(module);
            InjectDummyResources(module);
            InjectOverloadedMethods(module);
            InjectDummyModuleAttributes(module);
        }

        private void InjectDummyInterfaces(ModuleDef module)
        {
            int count = rng.Next(12, 24);
            for (int i = 0; i < count; i++)
            {
                var iface = new TypeDefUser("", engine.MakeName(),
                    null);
                iface.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Interface |
                    DnTypeAttributes.Abstract;
                module.Types.Add(iface);
                engine.injectedTypes.Add(iface);

                int methodCount = rng.Next(2, 6);
                for (int m = 0; m < methodCount; m++)
                {
                    int paramCount = rng.Next(0, 4);
                    var paramTypes = new TypeSig[paramCount];
                    for (int p = 0; p < paramCount; p++)
                        paramTypes[p] = GetRandomType(module);

                    var retType = rng.Next(0, 3) == 0 ? module.CorLibTypes.Void : GetRandomType(module);

                    var ifaceMethod = new MethodDefUser(engine.MakeName(),
                        MethodSig.CreateInstance(retType, paramTypes),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Public | DnMethodAttributes.Abstract |
                        DnMethodAttributes.Virtual | DnMethodAttributes.HideBySig |
                        DnMethodAttributes.NewSlot);
                    iface.Methods.Add(ifaceMethod);
                    engine.injectedMethods.Add(ifaceMethod);
                }

                for (int f = 0; f < rng.Next(0, 3); f++)
                {
                    var prop = new PropertyDefUser(engine.MakeName(),
                        new PropertySig(true, GetRandomType(module)));
                    iface.Properties.Add(prop);
                }
            }
        }

        private void InjectPInvokeDecoys(ModuleDef module)
        {
            string[][] pinvokeDecoys = new string[][]
            {
                new string[] { "kernel32.dll", "GetTickCount" },
                new string[] { "kernel32.dll", "GetCurrentProcessId" },
                new string[] { "kernel32.dll", "GetLastError" },
                new string[] { "user32.dll", "GetForegroundWindow" },
                new string[] { "ntdll.dll", "NtQueryInformationProcess" },
                new string[] { "kernel32.dll", "IsDebuggerPresent" },
                new string[] { "advapi32.dll", "GetUserNameW" },
                new string[] { "kernel32.dll", "GetModuleHandleA" },
            };

            var pinvokeHost = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            pinvokeHost.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed;
            module.Types.Add(pinvokeHost);
            engine.injectedTypes.Add(pinvokeHost);

            int decoyCount = rng.Next(10, 20);
            for (int i = 0; i < decoyCount; i++)
            {
                var pair = pinvokeDecoys[rng.Next(0, pinvokeDecoys.Length)];

                var pMethod = new MethodDefUser(engine.MakeName(),
                    MethodSig.CreateStatic(module.CorLibTypes.Int32),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

                pMethod.Body = new CilBody();
                pMethod.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                pMethod.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                pinvokeHost.Methods.Add(pMethod);
                engine.injectedMethods.Add(pMethod);
            }

            for (int f = 0; f < rng.Next(3, 6); f++)
            {
                pinvokeHost.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.IntPtr),
                    DnFieldAttributes.Private | DnFieldAttributes.Static));
            }
        }

        private void InjectDummyGenericTypes(ModuleDef module)
        {
            int count = rng.Next(8, 18);
            for (int i = 0; i < count; i++)
            {
                var genType = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                genType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.BeforeFieldInit;
                module.Types.Add(genType);
                engine.injectedTypes.Add(genType);

                int gpCount = rng.Next(1, 4);
                for (int g = 0; g < gpCount; g++)
                {
                    var gp = new GenericParamUser((ushort)g, GenericParamAttributes.NonVariant, engine.MakeName(4));
                    genType.GenericParameters.Add(gp);
                }

                for (int f = 0; f < rng.Next(2, 5); f++)
                {
                    genType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }

                var staticMethod = new MethodDefUser(engine.MakeName(),
                    MethodSig.CreateStatic(module.CorLibTypes.Int32),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
                staticMethod.Body = new CilBody();
                var il = staticMethod.Body.Instructions;

                for (int j = 0; j < rng.Next(3, 8); j++)
                {
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Pop));
                }
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                il.Add(Instruction.Create(DnOpCodes.Ret));

                genType.Methods.Add(staticMethod);
                engine.injectedMethods.Add(staticMethod);
            }
        }

        private void InjectDummyResources(ModuleDef module)
        {
            int count = rng.Next(6, 14);
            for (int i = 0; i < count; i++)
            {
                string resName = engine.MakeName() + ".resources";
                byte[] resData = new byte[rng.Next(64, 256)];
                for (int j = 0; j < resData.Length; j++)
                    resData[j] = (byte)rng.Next(0, 256);

                var embRes = new EmbeddedResource(resName, resData,
                    ManifestResourceAttributes.Private);
                module.Resources.Add(embRes);
            }
        }

        private void InjectOverloadedMethods(ModuleDef module)
        {
            int count = rng.Next(6, 12);
            for (int i = 0; i < count; i++)
            {
                var host = new TypeDefUser("", engine.MakeName(),
                    module.CorLibTypes.Object.TypeDefOrRef);
                host.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                    DnTypeAttributes.Sealed;
                module.Types.Add(host);
                engine.injectedTypes.Add(host);

                string methodBaseName = engine.MakeName();
                int overloadCount = rng.Next(7, 16);

                for (int o = 0; o < overloadCount; o++)
                {
                    int paramCount = o;
                    var paramTypes = new TypeSig[paramCount];
                    for (int p = 0; p < paramCount; p++)
                        paramTypes[p] = module.CorLibTypes.Int32;

                    var overload = new MethodDefUser(methodBaseName,
                        MethodSig.CreateStatic(module.CorLibTypes.Int32, paramTypes),
                        DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                        DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);

                    overload.Body = new CilBody();
                    overload.Body.InitLocals = true;
                    overload.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
                    var il = overload.Body.Instructions;

                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rng.Next()));
                    il.Add(Instruction.Create(DnOpCodes.Stloc_0));

                    for (int p = 0; p < paramCount; p++)
                    {
                        il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                        switch (p)
                        {
                            case 0: il.Add(Instruction.Create(DnOpCodes.Ldarg_0)); break;
                            case 1: il.Add(Instruction.Create(DnOpCodes.Ldarg_1)); break;
                            case 2: il.Add(Instruction.Create(DnOpCodes.Ldarg_2)); break;
                            case 3: il.Add(Instruction.Create(DnOpCodes.Ldarg_3)); break;
                            default: il.Add(Instruction.Create(DnOpCodes.Ldarg, overload.Parameters[p])); break;
                        }
                        il.Add(Instruction.Create(DnOpCodes.Xor));
                        il.Add(Instruction.Create(DnOpCodes.Stloc_0));
                    }

                    il.Add(Instruction.Create(DnOpCodes.Ldloc_0));
                    il.Add(Instruction.Create(DnOpCodes.Ret));

                    host.Methods.Add(overload);
                    engine.injectedMethods.Add(overload);
                }

                for (int f = 0; f < rng.Next(2, 5); f++)
                {
                    host.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(module.CorLibTypes.Int32),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }
            }
        }

        private void InjectDummyModuleAttributes(ModuleDef module)
        {
            var attrHost = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.GetTypeRef("System", "Attribute"));
            attrHost.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Sealed;
            module.Types.Add(attrHost);
            engine.injectedTypes.Add(attrHost);

            var ctor = new MethodDefUser(".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Public | DnMethodAttributes.HideBySig |
                DnMethodAttributes.SpecialName | DnMethodAttributes.RTSpecialName);
            ctor.Body = new CilBody();
            ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ldarg_0));
            var baseCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                module.CorLibTypes.GetTypeRef("System", "Attribute"));
            ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Call, baseCtor));
            ctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            attrHost.Methods.Add(ctor);
            engine.injectedMethods.Add(ctor);

            for (int f = 0; f < rng.Next(2, 5); f++)
            {
                attrHost.Fields.Add(new FieldDefUser(engine.MakeName(),
                    new FieldSig(module.CorLibTypes.String),
                    DnFieldAttributes.Private));
            }

            string[] caValues = new string[]
            {
                "Licensed Software", "Internal Build", "Service Component",
                "Release Channel", "Build Configuration", "Distribution",
                "Verified Component", "Standard Release", "Production Build",
                "Approved Component", "Runtime Module", "System Component"
            };

            int caCount = rng.Next(8, 16);
            for (int i = 0; i < caCount; i++)
            {
                var ca = new CustomAttribute(ctor);
                ca.ConstructorArguments.Add(new CAArgument(module.CorLibTypes.String,
                    caValues[rng.Next(0, caValues.Length)]));

                if (module.Assembly != null)
                    module.Assembly.CustomAttributes.Add(ca);
            }
        }

        private TypeSig GetRandomType(ModuleDef module)
        {
            int t = rng.Next(0, 8);
            switch (t)
            {
                case 0: return module.CorLibTypes.Int32;
                case 1: return module.CorLibTypes.String;
                case 2: return module.CorLibTypes.Boolean;
                case 3: return module.CorLibTypes.Object;
                case 4: return module.CorLibTypes.Int64;
                case 5: return module.CorLibTypes.Byte;
                case 6: return new SZArraySig(module.CorLibTypes.Byte);
                default: return module.CorLibTypes.Double;
            }
        }
    }
}

