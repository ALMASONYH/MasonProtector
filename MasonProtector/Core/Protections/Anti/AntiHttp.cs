using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class AntiHttpProtection
    {
        private readonly Obfuscation engine;
        private readonly Random rng;

        internal AntiHttpProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyAntiHttp(ModuleDef module, TypeDef modType)
        {
            var antiType = new TypeDefUser("", engine.MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            antiType.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(antiType);
            engine.injectedTypes.Add(antiType);

            var initMethod = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static | DnMethodAttributes.HideBySig);
            initMethod.Body = new CilBody();
            initMethod.Body.InitLocals = true;

            var il = initMethod.Body.Instructions;

            var setSecProto = module.Import(typeof(System.Net.ServicePointManager).GetProperty("SecurityProtocol").GetSetMethod());
            var getSecProto = module.Import(typeof(System.Net.ServicePointManager).GetProperty("SecurityProtocol").GetGetMethod());

            var afterTry = Instruction.Create(DnOpCodes.Ret);

            var tryStart = Instruction.Create(DnOpCodes.Call, getSecProto);
            il.Add(tryStart);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 3072));
            il.Add(Instruction.Create(DnOpCodes.Or));
            il.Add(Instruction.Create(DnOpCodes.Call, setSecProto));

            il.Add(Instruction.Create(DnOpCodes.Leave, afterTry));

            var handlerStart = Instruction.Create(DnOpCodes.Pop);
            il.Add(handlerStart);
            il.Add(Instruction.Create(DnOpCodes.Leave, afterTry));
            il.Add(afterTry);

            initMethod.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = afterTry,

                CatchType = new TypeRefUser(module, "System", "Exception",
                    module.CorLibTypes.AssemblyRef),
            });

            antiType.Methods.Add(initMethod);
            engine.injectedMethods.Add(initMethod);
            engine.InjectCallInCctor(module, modType, initMethod);
        }
    }
}

