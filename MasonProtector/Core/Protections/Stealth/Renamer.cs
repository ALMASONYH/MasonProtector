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
    internal class RenamerProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal RenamerProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        private Dictionary<string, string> _nsRenameMap;

        internal void ApplyRenamer(ModuleDef module, PreAnalysis.AnalysisResult analysis)
        {
            var resourceRenames = new Dictionary<string, string>();
            _nsRenameMap = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (TypeDef type in module.GetTypes())
            {
                if (type.Name == "<Module>" || type.IsGlobalModuleType) continue;
                if (type.IsRuntimeSpecialName || type.IsSpecialName) continue;
                if (engine.IsCompilerGenerated(type)) continue;

                if (engine.IsTypeUserExcluded(type)) continue;

                bool isSerializable = analysis != null && analysis.SerializableTypes.Contains(type);
                bool safeToRenameType = !isSerializable;

                string oldFullName = type.FullName;

                if (engine.cfg.RenameNamespaces && !isSerializable)
                    AssignUniqueNamespace(type);

                if (engine.cfg.RenameTypes && safeToRenameType && CanRenameType(type))
                    type.Name = GenerateObfuscatedName();

                string newFullName = type.FullName;
                if (oldFullName != newFullName)
                {
                    string oldRes = oldFullName.Replace('/', '.') + ".resources";
                    string newRes = newFullName.Replace('/', '.') + ".resources";
                    resourceRenames[oldRes] = newRes;
                }

                if (engine.cfg.RenameMethods && !isSerializable)
                {
                    foreach (MethodDef m in type.Methods)
                    {
                        if (CanRenameMethod(module, m))
                        {
                            m.Name = GenerateObfuscatedName();
                            foreach (var p in m.Parameters)
                            {
                                if (p.ParamDef != null && !string.IsNullOrEmpty(p.Name))
                                    p.ParamDef.Name = GenerateObfuscatedName();
                            }
                        }
                    }
                }

                if (engine.cfg.RenameFields && !isSerializable)
                {
                    foreach (FieldDef f in type.Fields)
                    {
                        if (CanRenameField(f))
                            f.Name = GenerateObfuscatedName();
                    }
                }

                if (engine.cfg.RenameProperties && !isSerializable)
                {
                    foreach (PropertyDef p in type.Properties)
                    {
                        if (CanRenameProperty(p))
                        {
                            string oldPropName = p.Name;
                            p.Name = GenerateObfuscatedName();

                            if (p.GetMethod != null && !p.GetMethod.IsPublic && !p.GetMethod.IsAbstract)
                                p.GetMethod.Name = GenerateObfuscatedName();
                            if (p.SetMethod != null && !p.SetMethod.IsPublic && !p.SetMethod.IsAbstract)
                                p.SetMethod.Name = GenerateObfuscatedName();

                            StripAccessedThroughProperty(type, oldPropName);
                        }
                    }
                }

                if (engine.cfg.RenameEvents && !isSerializable)
                {
                    foreach (EventDef ev in type.Events)
                    {
                        if (CanRenameEvent(ev))
                        {
                            ev.Name = GenerateObfuscatedName();
                            if (ev.AddMethod != null && !ev.AddMethod.IsPublic && !ev.AddMethod.IsAbstract)
                                ev.AddMethod.Name = GenerateObfuscatedName();
                            if (ev.RemoveMethod != null && !ev.RemoveMethod.IsPublic && !ev.RemoveMethod.IsAbstract)
                                ev.RemoveMethod.Name = GenerateObfuscatedName();
                        }
                    }
                }
            }

            foreach (TypeDef type in module.GetTypes())
            {
                if (!engine.IsCompilerGenerated(type)) continue;
                if (engine.injectedTypes.Contains(type)) continue;
                if (type.IsGlobalModuleType || type.Name == "<Module>") continue;
                if (type.IsRuntimeSpecialName || type.IsSpecialName) continue;
                if (type.Name.StartsWith("<PrivateImplementationDetails>")) continue;
                if (type.Name.StartsWith("__StaticArrayInit")) continue;

                if (engine.IsTypeUserExcluded(type)) continue;

                string oldFullName = type.FullName;

                if (engine.cfg.RenameNamespaces)
                    AssignUniqueNamespace(type);

                if (engine.cfg.RenameTypes && CanRenameType(type))
                    type.Name = GenerateObfuscatedName();

                string newFullName = type.FullName;
                if (oldFullName != newFullName)
                {
                    string oldRes = oldFullName.Replace('/', '.') + ".resources";
                    string newRes = newFullName.Replace('/', '.') + ".resources";
                    resourceRenames[oldRes] = newRes;
                }

                if (engine.cfg.RenameFields)
                {
                    foreach (FieldDef f in type.Fields)
                    {
                        if (CanRenameField(f))
                            f.Name = GenerateObfuscatedName();
                    }
                }

                if (engine.cfg.RenameMethods)
                {
                    foreach (MethodDef m in type.Methods)
                    {
                        if (CanRenameMethod(module, m))
                            m.Name = GenerateObfuscatedName();
                    }
                }

                if (engine.cfg.RenameProperties)
                {
                    foreach (PropertyDef p in type.Properties)
                    {
                        if (!CanRenameProperty(p)) continue;
                        string oldPropName = p.Name;
                        p.Name = GenerateObfuscatedName();
                        if (p.GetMethod != null && !p.GetMethod.IsPublic && !p.GetMethod.IsAbstract)
                            p.GetMethod.Name = GenerateObfuscatedName();
                        if (p.SetMethod != null && !p.SetMethod.IsPublic && !p.SetMethod.IsAbstract)
                            p.SetMethod.Name = GenerateObfuscatedName();
                        StripAccessedThroughProperty(type, oldPropName);
                    }
                }

                if (engine.cfg.RenameEvents)
                {
                    foreach (EventDef ev in type.Events)
                    {
                        if (!CanRenameEvent(ev)) continue;
                        ev.Name = GenerateObfuscatedName();
                        if (ev.AddMethod != null && !ev.AddMethod.IsPublic && !ev.AddMethod.IsAbstract)
                            ev.AddMethod.Name = GenerateObfuscatedName();
                        if (ev.RemoveMethod != null && !ev.RemoveMethod.IsPublic && !ev.RemoveMethod.IsAbstract)
                            ev.RemoveMethod.Name = GenerateObfuscatedName();
                    }
                }
            }

            foreach (var res in module.Resources)
            {
                EmbeddedResource emb = res as EmbeddedResource;
                if (emb != null && resourceRenames.ContainsKey(emb.Name))
                    emb.Name = resourceRenames[emb.Name];
            }

            if (resourceRenames.Count > 0)
                RewriteResourceLiterals(module, resourceRenames);
        }

        private static void StripAccessedThroughProperty(TypeDef type, string oldPropName)
        {
            foreach (FieldDef field in type.Fields)
            {
                for (int ci = field.CustomAttributes.Count - 1; ci >= 0; ci--)
                {
                    var ca = field.CustomAttributes[ci];
                    if (ca.AttributeType == null) continue;
                    if (ca.AttributeType.FullName !=
                        "System.Runtime.CompilerServices.AccessedThroughPropertyAttribute") continue;
                    if (ca.ConstructorArguments.Count == 0) continue;
                    object v = ca.ConstructorArguments[0].Value;
                    if (v != null && v.ToString() == oldPropName)
                    {
                        field.CustomAttributes.RemoveAt(ci);
                        break;
                    }
                }
            }
        }

        private static void RewriteResourceLiterals(ModuleDef module, Dictionary<string, string> resourceRenames)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                foreach (MethodDef m in type.Methods)
                {
                    if (!m.HasBody || !m.Body.HasInstructions) continue;
                    var il = m.Body.Instructions;
                    for (int i = 0; i < il.Count; i++)
                    {
                        if (il[i].OpCode != DnOpCodes.Ldstr) continue;
                        string s = il[i].Operand as string;
                        if (string.IsNullOrEmpty(s)) continue;

                        string mapped;
                        if (s.EndsWith(".resources", StringComparison.Ordinal) &&
                            resourceRenames.TryGetValue(s, out mapped))
                        {
                            il[i].Operand = mapped;
                            continue;
                        }

                        string lookupKey = s + ".resources";
                        if (resourceRenames.TryGetValue(lookupKey, out mapped))
                        {
                            il[i].Operand = mapped.Substring(0, mapped.Length - ".resources".Length);
                        }
                    }
                }
            }
        }

        private static string[] _phraseWords;
        private static readonly object _phraseWordsLock = new object();
        private HashSet<string> _issuedPhrases = new HashSet<string>(StringComparer.Ordinal);

        internal static string[] LoadPhraseWordsInternal()
        {
            return LoadPhraseWords();
        }

        private static string[] LoadPhraseWords()
        {
            if (_phraseWords != null) return _phraseWords;
            lock (_phraseWordsLock)
            {
                if (_phraseWords != null) return _phraseWords;
                try
                {
                    var asm = typeof(RenamerProtection).Assembly;
                    string resName = null;
                    foreach (var name in asm.GetManifestResourceNames())
                    {
                        if (name.EndsWith("freemasonry.txt", StringComparison.OrdinalIgnoreCase))
                        {
                            resName = name;
                            break;
                        }
                    }
                    if (resName == null) { _phraseWords = new string[0]; return _phraseWords; }
                    using (var stm = asm.GetManifestResourceStream(resName))
                    {
                        if (stm == null) { _phraseWords = new string[0]; return _phraseWords; }
                        using (var rdr = new System.IO.StreamReader(stm, Encoding.UTF8))
                        {
                            var list = new List<string>();
                            string line;
                            while ((line = rdr.ReadLine()) != null)
                            {
                                line = line.Trim();
                                if (line.Length < 3) continue;
                                bool ok = true;
                                foreach (var c in line)
                                {
                                    if (!char.IsLetter(c)) { ok = false; break; }
                                }
                                if (!ok) continue;
                                list.Add(char.ToUpperInvariant(line[0]) + line.Substring(1).ToLowerInvariant());
                            }
                            _phraseWords = list.ToArray();
                            return _phraseWords;
                        }
                    }
                }
                catch
                {
                    _phraseWords = new string[0];
                    return _phraseWords;
                }
            }
        }

        private string GenerateHiddenName()
        {
            var words = LoadPhraseWords();
            if (words == null || words.Length < 2)
            {
                int len = rng.Next(16, 48);
                return engine.GenerateStyledName(len, true);
            }

            for (int attempt = 0; attempt < 12; attempt++)
            {
                int parts = rng.Next(2, 5);
                var sb = new StringBuilder();
                for (int i = 0; i < parts; i++)
                    sb.Append(words[rng.Next(words.Length)]);
                string candidate = sb.ToString();
                if (candidate.Length > 64) candidate = candidate.Substring(0, 64);
                if (_issuedPhrases.Add(candidate)) return candidate;
            }

            string fallback;
            int tries = 0;
            do
            {
                int parts2 = rng.Next(2, 5);
                var sb2 = new StringBuilder();
                for (int i = 0; i < parts2; i++)
                    sb2.Append(words[rng.Next(words.Length)]);
                sb2.Append(rng.Next(100, 99999).ToString());
                fallback = sb2.ToString();
                if (fallback.Length > 80) fallback = fallback.Substring(0, 80);
                tries++;
            } while (!_issuedPhrases.Add(fallback) && tries < 16);
            return fallback;
        }

        private string GenerateObfuscatedName()
        {

            if (engine.cfg != null && engine.cfg.MaximumEncryption)
                return engine.GenerateStyledName(rng.Next(50, 91), true);
            if (engine.cfg != null && engine.cfg.HiddenRename)
                return GenerateHiddenName();
            int length = rng.Next(16, 48);
            return engine.GenerateStyledName(length, true);
        }

        private void AssignUniqueNamespace(TypeDef type)
        {
            if (engine.preserveNamespaceTypes.Contains(type)) return;
            if (string.IsNullOrEmpty(type.Namespace)) return;

            bool perClass = engine.cfg != null && engine.cfg.SeparateNamespacePerClass;
            if (perClass)
            {
                type.Namespace = GenerateObfuscatedName();
                return;
            }

            string originalNs = type.Namespace;
            string mapped;
            if (_nsRenameMap == null) _nsRenameMap = new Dictionary<string, string>(StringComparer.Ordinal);
            if (!_nsRenameMap.TryGetValue(originalNs, out mapped))
            {
                mapped = GenerateObfuscatedName();
                _nsRenameMap[originalNs] = mapped;
            }
            type.Namespace = mapped;
        }

        internal void ApplyLateInjectedRemap(ModuleDef module)
        {
            if (!engine.cfg.EnableRenamer) return;

            foreach (TypeDef type in module.GetTypes())
            {
                if (engine.preserveNamespaceTypes.Contains(type)) continue;
                if (engine.preserveNameTypes.Contains(type)) continue;
                if (!engine.injectedTypes.Contains(type)) continue;
                if (type.IsGlobalModuleType || type.Name == "<Module>") continue;
                if (type.IsRuntimeSpecialName || type.IsSpecialName) continue;

                if (engine.cfg.RenameNamespaces && !string.IsNullOrEmpty(type.Namespace))
                    type.Namespace = GenerateObfuscatedName();

                if (engine.cfg.RenameTypes && CanRenameType(type))
                    type.Name = GenerateObfuscatedName();

                if (engine.cfg.RenameFields)
                {
                    foreach (FieldDef f in type.Fields)
                    {
                        if (CanRenameField(f))
                            f.Name = GenerateObfuscatedName();
                    }
                }

                if (engine.cfg.RenameMethods)
                {
                    foreach (MethodDef m in type.Methods)
                    {
                        if (CanRenameMethod(module, m))
                        {
                            m.Name = GenerateObfuscatedName();
                            foreach (var p in m.Parameters)
                            {
                                if (p.ParamDef != null && !string.IsNullOrEmpty(p.Name))
                                    p.ParamDef.Name = GenerateObfuscatedName();
                            }
                        }
                    }
                }

                if (engine.cfg.RenameProperties)
                {
                    foreach (PropertyDef p in type.Properties)
                    {
                        if (!CanRenameProperty(p)) continue;
                        string oldPropName = p.Name;
                        p.Name = GenerateObfuscatedName();
                        if (p.GetMethod != null && !p.GetMethod.IsPublic && !p.GetMethod.IsAbstract)
                            p.GetMethod.Name = GenerateObfuscatedName();
                        if (p.SetMethod != null && !p.SetMethod.IsPublic && !p.SetMethod.IsAbstract)
                            p.SetMethod.Name = GenerateObfuscatedName();
                        StripAccessedThroughProperty(type, oldPropName);
                    }
                }

                if (engine.cfg.RenameEvents)
                {
                    foreach (EventDef ev in type.Events)
                    {
                        if (!CanRenameEvent(ev)) continue;
                        ev.Name = GenerateObfuscatedName();
                        if (ev.AddMethod != null && !ev.AddMethod.IsPublic && !ev.AddMethod.IsAbstract)
                            ev.AddMethod.Name = GenerateObfuscatedName();
                        if (ev.RemoveMethod != null && !ev.RemoveMethod.IsPublic && !ev.RemoveMethod.IsAbstract)
                            ev.RemoveMethod.Name = GenerateObfuscatedName();
                    }
                }
            }
        }

        private static bool IsComVisibleType(TypeDef t)
        {
            if (t == null || t.CustomAttributes == null) return false;
            foreach (var ca in t.CustomAttributes)
            {
                if (ca.AttributeType == null) continue;
                if (ca.AttributeType.FullName != "System.Runtime.InteropServices.ComVisibleAttribute") continue;
                if (ca.ConstructorArguments != null && ca.ConstructorArguments.Count > 0)
                {
                    var v = ca.ConstructorArguments[0].Value;
                    if (v is bool) return (bool)v;
                }
                return true;
            }
            return false;
        }

        private bool CanRenameType(TypeDef t)
        {
            if (t.IsRuntimeSpecialName || t.IsSpecialName) return false;
            if (t.Name.StartsWith("<")) return false;
            if (t.IsForwarder) return false;
            if (IsComVisibleType(t)) return false;

            if (engine.IsTypeUserExcluded(t)) return false;
            return true;
        }

        private bool CanRenameMethod(ModuleDef module, MethodDef m)
        {
            if (m.IsRuntimeSpecialName || m.IsSpecialName) return false;
            if (m.IsConstructor) return false;
            if (m.Name == "Main") return false;

            if (m.Name == "InitializeComponent" &&
                (engine.cfg == null || !engine.cfg.MaximumEncryption))
                return false;
            if (m.Name.StartsWith("<")) return false;
            if (module.EntryPoint == m) return false;
            if (m.IsPinvokeImpl) return false;
            if (m.DeclaringType != null && m.DeclaringType.IsDelegate) return false;
            if (m.IsVirtual || m.IsAbstract) return false;
            if (m.DeclaringType != null && m.DeclaringType.HasGenericParameters) return false;
            if (IsComVisibleType(m.DeclaringType)) return false;

            if (engine.IsMethodUserExcluded(m)) return false;
            return true;
        }

        private bool CanRenameField(FieldDef f)
        {
            if (f.IsRuntimeSpecialName || f.IsSpecialName) return false;
            if (f.Name.StartsWith("<")) return false;
            if (f.DeclaringType != null && f.DeclaringType.HasGenericParameters) return false;
            if (IsComVisibleType(f.DeclaringType)) return false;

            if (f.DeclaringType != null && engine.IsTypeUserExcluded(f.DeclaringType)) return false;

            foreach (var ca in f.CustomAttributes)
            {
                if (ca.AttributeType != null &&
                    ca.AttributeType.FullName == "System.ThreadStaticAttribute")
                    return false;
            }

            if (f.IsLiteral && f.DeclaringType != null && f.DeclaringType.IsEnum) return false;

            if (f.IsLiteral)
            {
                foreach (var ca in f.CustomAttributes)
                {
                    if (ca.AttributeType == null) continue;
                    string an = ca.AttributeType.FullName;
                    if (an == "System.Runtime.Serialization.EnumMemberAttribute") return false;
                    if (an == "System.Xml.Serialization.XmlEnumAttribute") return false;
                    if (an == "Newtonsoft.Json.JsonPropertyAttribute") return false;
                }
            }
            return true;
        }

        private static readonly HashSet<string> propertyDangerousAttrs = new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Xml.Serialization.XmlElementAttribute",
            "System.Xml.Serialization.XmlAttributeAttribute",
            "System.Xml.Serialization.XmlArrayAttribute",
            "System.Xml.Serialization.XmlArrayItemAttribute",
            "System.Runtime.Serialization.DataMemberAttribute",
            "Newtonsoft.Json.JsonPropertyAttribute",
            "System.Text.Json.Serialization.JsonPropertyNameAttribute",
            "System.ComponentModel.DataAnnotations.Schema.ColumnAttribute",
            "System.ComponentModel.BindableAttribute",
        };

        private bool CanRenameProperty(PropertyDef p)
        {
            if (p.IsRuntimeSpecialName || p.IsSpecialName) return false;
            if (p.Name.StartsWith("<")) return false;
            if (p.DeclaringType != null && p.DeclaringType.HasGenericParameters) return false;
            if (IsComVisibleType(p.DeclaringType)) return false;
            if (p.DeclaringType != null && engine.IsTypeUserExcluded(p.DeclaringType)) return false;

            if (p.GetMethod != null && p.GetMethod.IsPublic &&
                (p.GetMethod.IsVirtual || p.GetMethod.IsAbstract)) return false;
            if (p.SetMethod != null && p.SetMethod.IsPublic &&
                (p.SetMethod.IsVirtual || p.SetMethod.IsAbstract)) return false;

            if (p.CustomAttributes.Count > 0)
            {
                bool isPublicAccessor = (p.GetMethod != null && p.GetMethod.IsPublic) ||
                                        (p.SetMethod != null && p.SetMethod.IsPublic);
                if (isPublicAccessor)
                {
                    foreach (var ca in p.CustomAttributes)
                    {
                        if (ca.AttributeType != null &&
                            propertyDangerousAttrs.Contains(ca.AttributeType.FullName))
                            return false;
                    }
                }
            }
            return true;
        }

        private bool CanRenameEvent(EventDef e)
        {
            if (e.IsRuntimeSpecialName || e.IsSpecialName) return false;
            if (e.Name.StartsWith("<")) return false;
            if (e.AddMethod != null && e.AddMethod.IsPublic &&
                (e.AddMethod.IsVirtual || e.AddMethod.IsAbstract)) return false;
            if (e.RemoveMethod != null && e.RemoveMethod.IsPublic &&
                (e.RemoveMethod.IsVirtual || e.RemoveMethod.IsAbstract)) return false;
            if (IsComVisibleType(e.DeclaringType)) return false;
            if (e.DeclaringType != null && engine.IsTypeUserExcluded(e.DeclaringType)) return false;
            return true;
        }
    }
}

