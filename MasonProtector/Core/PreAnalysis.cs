using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class PreAnalysis
    {
        private ModuleDef module;

        internal class AnalysisResult
        {
            public bool HasReflection { get; set; }
            public bool HasSerialization { get; set; }
            public HashSet<TypeDef> SerializableTypes { get; set; }
            public HashSet<MethodDef> ReflectionMethods { get; set; }

            public AnalysisResult()
            {
                SerializableTypes = new HashSet<TypeDef>();
                ReflectionMethods = new HashSet<MethodDef>();
            }
        }

        internal PreAnalysis(ModuleDef mod)
        {
            module = mod;
        }

        internal AnalysisResult Analyze()
        {
            var result = new AnalysisResult();

            foreach (TypeDef type in module.GetTypes())
            {
                ScanTypeForPatterns(type, result);
            }

            return result;
        }

        private void ScanTypeForPatterns(TypeDef type, AnalysisResult result)
        {
            if (type.IsSerializable)
            {
                result.HasSerialization = true;
                result.SerializableTypes.Add(type);
            }

            foreach (var iface in type.Interfaces)
            {
                if (iface.Interface != null)
                {
                    string ifName = iface.Interface.FullName;
                    if (ifName == "System.Runtime.Serialization.ISerializable" ||
                        ifName == "System.Runtime.Serialization.IDeserializationCallback")
                    {
                        result.HasSerialization = true;
                        result.SerializableTypes.Add(type);
                    }
                }
            }

            foreach (MethodDef method in type.Methods)
            {
                if (!method.HasBody || !method.Body.HasInstructions) continue;

                foreach (var inst in method.Body.Instructions)
                {
                    if (inst.OpCode != DnOpCodes.Call && inst.OpCode != DnOpCodes.Callvirt) continue;

                    var target = inst.Operand as IMethod;
                    if (target == null) continue;

                    string declType = target.DeclaringType.FullName;
                    string mName = target.Name;

                    if (declType == "System.Type" || declType == "System.Reflection.Assembly" ||
                        declType == "System.Activator")
                    {
                        if (mName == "GetMethod" || mName == "GetType" || mName == "GetField" ||
                            mName == "GetProperty" || mName == "CreateInstance" || mName == "InvokeMember" ||
                            mName == "GetMethods" || mName == "GetFields")
                        {
                            result.HasReflection = true;
                            result.ReflectionMethods.Add(method);
                        }
                    }
                }
            }
        }
    }
}

