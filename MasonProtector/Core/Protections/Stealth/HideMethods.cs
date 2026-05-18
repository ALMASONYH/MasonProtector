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
    internal class HideMethodsProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal HideMethodsProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyHideMethods(ModuleDef module)
        {
            var compGenTypeRef = module.Import(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute)) as TypeRef;
            var compGenRef = compGenTypeRef != null ? compGenTypeRef.Resolve() : null;
            var compGenCtor = compGenRef != null ? compGenRef.FindDefaultConstructor() : null;
            ICustomAttributeType compGenCtorRef = compGenCtor != null ? module.Import(compGenCtor) : null;

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.IsCompilerGenerated(type)) continue;

                if (engine.IsTypeUserExcluded(type)) continue;

                bool isPublicApiType = type.IsPublic || type.IsNestedPublic;

                foreach (MethodDef method in type.Methods)
                {
                    if (engine.injectedMethods.Contains(method)) continue;
                    if (method.IsConstructor) continue;
                    if (engine.IsMethodUserExcluded(method)) continue;

                    bool isPublicApiMethod = isPublicApiType &&
                        (method.IsPublic || method.IsFamilyOrAssembly || method.IsFamily);

                    if (compGenCtorRef != null && !isPublicApiMethod)
                    {
                        bool hasAttr = method.CustomAttributes.Any(
                            ca => ca.AttributeType.FullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute");
                        if (!hasAttr)
                        {
                            method.CustomAttributes.Add(new CustomAttribute(compGenCtorRef));
                        }
                    }

                    method.IsAggressiveInlining = false;

                }
            }
        }
    }
}

