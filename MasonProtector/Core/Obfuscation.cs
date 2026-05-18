using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnTypeAttributes = dnlib.DotNet.TypeAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class Obfuscation
    {
        private PolyEngine poly;
        private PreAnalysis analyzer;
        internal Random rng;
        internal string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        internal int nameCounter = 0;

        private HashSet<int> issuedNameSuffixes = new HashSet<int>();
        internal ProtectionSettings cfg;
        internal HashSet<MethodDef> injectedMethods = new HashSet<MethodDef>();
        internal HashSet<TypeDef> injectedTypes = new HashSet<TypeDef>();

        internal HashSet<MethodDef> bodyVaultedStubs = new HashSet<MethodDef>();
        internal HashSet<MethodDef> controlFlowFlattenedMethods = new HashSet<MethodDef>();
        internal HashSet<MethodDef> virtualizedMethods = new HashSet<MethodDef>();
        internal HashSet<MethodDef> designerSplitSubMethods = new HashSet<MethodDef>();

        internal MethodDef antiCrackOnDetection;

        internal HashSet<TypeDef> lateStringEncryptionExcludedTypes = new HashSet<TypeDef>();

        internal HashSet<string> userExcluded = new HashSet<string>(StringComparer.Ordinal);

        internal bool IsNamespaceUserExcluded(string ns)
        {
            if (string.IsNullOrEmpty(ns)) return false;
            return userExcluded.Contains("ns:" + ns);
        }

        internal bool IsTypeUserExcluded(TypeDef t)
        {
            if (t == null) return false;
            if (userExcluded.Count == 0) return false;
            if (userExcluded.Contains(t.FullName)) return true;
            if (!string.IsNullOrEmpty(t.Namespace) &&
                userExcluded.Contains("ns:" + t.Namespace)) return true;

            if (t.DeclaringType != null && IsTypeUserExcluded(t.DeclaringType)) return true;
            return false;
        }

        internal bool IsMethodUserExcluded(MethodDef m)
        {
            if (m == null) return false;
            if (userExcluded.Count == 0) return false;
            if (userExcluded.Contains(m.FullName)) return true;
            if (m.DeclaringType != null && IsTypeUserExcluded(m.DeclaringType)) return true;
            return false;
        }

        internal void EmitAntiCrackHook(IList<Instruction> il)
        {
            if (antiCrackOnDetection == null || il == null) return;
            il.Add(Instruction.Create(DnOpCodes.Call, antiCrackOnDetection));
        }
        internal HashSet<TypeDef> preserveNamespaceTypes = new HashSet<TypeDef>();
        internal HashSet<TypeDef> preserveNameTypes = new HashSet<TypeDef>();
        internal HashSet<string> injectedResources = new HashSet<string>(StringComparer.Ordinal);
        internal NativeShroud antiShroud;

        internal int nameStyle = 0;

        public void PerformProtection(string inputPath, string outputPath, ProtectionSettings settings,
            Action<string> updateStatus, Action<int> updateProgress)
        {
            cfg = settings;
            nameCounter = 0;
            issuedNameSuffixes.Clear();
            injectedMethods.Clear();
            injectedTypes.Clear();
            lateStringEncryptionExcludedTypes.Clear();
            bodyVaultedStubs.Clear();
            preserveNamespaceTypes.Clear();
            preserveNameTypes.Clear();
            injectedResources.Clear();
            antiShroud = null;

            byte[] seed = new byte[4];
            using (var csp = new RNGCryptoServiceProvider())
                csp.GetBytes(seed);
            rng = new Random(BitConverter.ToInt32(seed, 0));

            if (!string.IsNullOrEmpty(settings.RandomChars))
                charset = settings.RandomChars;

            if (string.IsNullOrEmpty(charset))
                charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

            poly = new PolyEngine(rng);

            nameStyle = rng.Next(0, 4);

            ModuleDefMD module = ModuleDefMD.Load(inputPath);
            TypeDef modType = module.Types.FirstOrDefault(t => t.Name == "<Module>");

            if (modType == null)
                throw new InvalidOperationException("Target assembly missing <Module> type");

            analyzer = new PreAnalysis(module);
            var analysisResult = analyzer.Analyze();

            if (settings.EnableRenamer && analysisResult.HasReflection)
                updateStatus("Warning: Assembly uses reflection, renamer may cause issues");

            ResolveConflicts(settings, analysisResult);

            if (settings.MaximumEncryption)
            {

                string[] panicStack = new string[]
                {

                    "EnableRenamer", "RenameNamespaces", "SeparateNamespacePerClass",
                    "RenameTypes", "RenameMethods", "RenameFields",
                    "RenameProperties", "RenameEvents",

                    "StringEncryption", "IntEncoding", "ConstantsEncoding",
                    "FieldEncryption", "PolymorphicEncryption",
                    "StringComposition",
                    "RuntimeEncryption", "MethodBodyEncryption", "DelegateEncryption",
                    "ResourceProtection",

                    "ControlFlow", "ControlFlowFlattening2", "BranchConfusion",
                    "OpaquePredicates", "NumericObfuscation",

                    "ProxyCalls", "ReferenceProxy", "CallHiding", "CalliConversion",
                    "Local2Field", "MethodInliner",

                    "JunkCode", "DnSpyCrasher",
                    "HideMethods", "FakeAttributes", "Watermark", "DecompilerPoison",
                    "HideDesignerCode", "EntryPointMover",

                    "AntiTamper", "AntiDump",
                    "AntiDe4dot", "AntiILDasm",

                };
                var psType = settings.GetType();
                foreach (string name in panicStack)
                {
                    var p = psType.GetProperty(name);
                    if (p == null || p.PropertyType != typeof(bool) || !p.CanWrite) continue;
                    p.SetValue(settings, true, null);
                }
            }

            int totalSteps = 50;
            int currentStep = 0;

            try
            {
                if (settings.AntiDe4dot)
                {
                    updateStatus("Injecting anti-de4dot traps...");
                    new AntiDe4dotProtection(this).ApplyAntiDe4dot(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.EnableRenamer)
                {
                    updateStatus("Renaming identifiers...");
                    new RenamerProtection(this).ApplyRenamer(module, analysisResult);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.VMObfuscation)
                {
                    updateStatus("Virtualizing methods...");
                    new VMObfuscationProtection(this).ApplyVMObfuscation(module);
                }
                if (settings.VMObfuscationV2 && !settings.ExportCodeToDll)
                {
                    updateStatus("Virtualizing methods (object-stack VM)...");
                    new VMObfuscationV2Protection(this).ApplyVMObfuscationV2(module);
                }
                else if (settings.VMObfuscationV2 && settings.ExportCodeToDll)
                {
                    updateStatus("VMObfuscationV2 skipped (incompatible with ExportCodeToDll).");
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.ResourceProtection)
                {
                    updateStatus("Protecting resources...");
                    new RuntimeEncryptionProtection(this).ApplyResourceProtection(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.HideDesignerCode)
                {
                    updateStatus("Splitting designer methods for body-vault...");
                    try
                    {
                        int chunks = new DesignerSplitProtection(this).ApplyDesignerSplit(module);
                        if (chunks > 0) updateStatus("Sliced IC into " + chunks + " body-vault candidates.");
                    }
                    catch { }
                }

                if (cfg.MaximumEncryption)
                {
                    updateStatus("Maximum Encryption: relocating designer sub bodies to <Module>...");
                    try
                    {
                        int moved = new MaxEncRelocatorProtection(this).Apply(module);
                        if (moved > 0) updateStatus("Relocated " + moved + " designer sub bodies to <Module>.");
                    }
                    catch { }
                }

                if (settings.RuntimeEncryption)
                {
                    updateStatus("Hiding method bodies in encrypted vault...");
                    try { new BodyVaultProtection(this).ApplyBodyVault(module, modType); }
                    catch { }
                }

                if (settings.StringEncryption)
                {
                    updateStatus("Encrypting strings (multi-layer)...");
                    new StringEncryptionProtection(this).ApplyStringEncryption(module, modType);

                    try
                    {
                        int n = new ConstStringStripperProtection(this).ApplyStripping(module);
                        updateStatus("Stripped " + n + " const-string blob entries.");
                    }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.RuntimeEncryption)
                {
                    updateStatus("Wrapping methods with Freemasonry skeleton...");
                    new RuntimeEncryptionProtection(this).ApplyRuntimeEncryption(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                try
                {
                    int wn = new EntryWrapperProtection(this).ApplyEntryWrappers(module);
                    if (wn > 0) updateStatus("Interposed " + wn + " cctor wrappers near entry-point.");
                }
                catch { }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.IntEncoding)
                {
                    updateStatus("Encoding integer constants...");
                    new IntEncodingProtection(this).ApplyIntEncoding(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.IntEncoding)
                {
                    try
                    {
                        int mn = new MutationIndirectionProtection(this).ApplyMutationIndirection(module);
                        if (mn > 0) updateStatus("Wrapped " + mn + " int constants through identity-call indirection.");
                    }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.MutationEncoding)
                {
                    updateStatus("Applying mutation transformations...");
                    new MutationEncodingProtection(this).ApplyMutationEncoding(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.ConstantsEncoding)
                {
                    updateStatus("Encoding constants (float/long/double)...");
                    new ConstantsEncodingProtection(this).ApplyConstantsEncoding(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.MethodBodyEncryption)
                {
                    updateStatus("Encrypting method bodies...");
                    new MethodBodyEncryptionProtection(this).ApplyMethodBodyEncryption(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.CrossReferenceEncryption)
                {
                    updateStatus("Encrypting cross-references...");
                    new CrossReferenceEncryptionProtection(this).ApplyCrossReferenceEncryption(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.FieldEncryption)
                {
                    updateStatus("Encrypting field access patterns...");
                    new FieldEncryptionProtection(this).ApplyFieldEncryption(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.PolymorphicEncryption)
                {
                    updateStatus("Applying polymorphic encryption...");
                    new PolymorphicEncryptionProtection(this).ApplyPolymorphicEncryption(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.StringComposition)
                {
                    updateStatus("Decomposing strings into char math...");
                    new StringCompositionProtection(this).ApplyStringComposition(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.ArrayEncryption)
                {
                    updateStatus("Encrypting array constants...");
                    new ArrayEncryptionProtection(this).ApplyArrayEncryption(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.NumericObfuscation)
                {
                    updateStatus("Obfuscating numeric constants...");
                    new NumericObfuscationProtection(this).ApplyNumericObfuscation(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.MethodInliner)
                {
                    updateStatus("Dissolving call sites via inlining...");
                    new MethodInlinerProtection(this).ApplyMethodInliner(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.ControlFlow)
                {
                    updateStatus("Flattening control flow...");
                    new ControlFlowProtection(this).ApplyControlFlow(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.Local2Field)
                {
                    updateStatus("Converting locals to fields...");
                    new Local2FieldProtection(this).ApplyLocal2Field(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.ProxyCalls)
                {
                    updateStatus("Building proxy delegate chains...");
                    new ProxyCallsProtection(this).ApplyProxyCalls(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.CodeEncryption)
                {
                    updateStatus("Wrapping calls in code-encryption helpers...");
                    try { new CodeEncryptionProtection(this).ApplyCodeEncryption(module); }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.Dynamic)
                {
                    updateStatus("Converting calls to dynamic calli dispatch...");
                    try { new DynamicProtection(this).ApplyDynamic(module, modType); }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.CalliConversion)
                {
                    updateStatus("Converting to indirect calls...");
                    new CalliConversionProtection(this).ApplyCalliConversion(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.OpaquePredicates)
                {
                    updateStatus("Injecting opaque predicates...");
                    new OpaquePredicateProtection(this).ApplyOpaquePredicates(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.ReferenceProxy)
                {
                    updateStatus("Building reference proxies...");
                    new ReferenceProxyProtection(this).ApplyReferenceProxy(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.CallHiding)
                {
                    updateStatus("Hiding call targets...");
                    new CallHidingProtection(this).ApplyCallHiding(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.MethodScattering)
                {
                    updateStatus("Scattering methods across types...");
                    new MethodScatteringProtection(this).ApplyMethodScattering(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.ControlFlowFlattening2)
                {
                    updateStatus("Advanced control flow flattening...");
                    new ControlFlowFlattening2Protection(this).ApplyControlFlowFlattening2(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiCrack)
                {
                    updateStatus("Installing anti-crack escalation pipeline...");
                    try
                    {
                        var ac = new AntiCrackProtection(this);
                        ac.Apply(module, modType, settings);
                        antiCrackOnDetection = ac.OnDetectionMethod;
                    }
                    catch (Exception acEx)
                    {

                        antiCrackOnDetection = null;
                        throw new Exception("AntiCrack initialization failed: " + acEx.Message, acEx);
                    }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiDebug)
                {
                    updateStatus("Injecting anti-debug layers...");
                    new AntiDebugProtection(this).ApplyAntiDebug(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiVM)
                {
                    updateStatus("Adding VM detection...");
                    new AntiVMProtection(this).ApplyAntiVM(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiDump)
                {
                    updateStatus("Protecting against memory dumps...");
                    new AntiDumpProtection(this).ApplyAntiDump(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiTamper)
                {
                    updateStatus("Computing integrity checksums...");
                    new AntiTamperProtection(this).ApplyAntiTamper(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiHook)
                {
                    updateStatus("Verifying API prologues against hooks...");
                    new AntiHookProtection(this).ApplyAntiHook(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiHttp)
                {
                    updateStatus("Locking down network sniffer surface...");
                    new AntiHttpProtection(this).ApplyAntiHttp(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.DnSpyCrasher)
                {
                    updateStatus("Planting decompiler trap metadata...");
                    new DnSpyCrasherProtection(this).ApplyDnSpyCrasher(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.HideMethods)
                {
                    updateStatus("Hiding methods from decompilers...");
                    new HideMethodsProtection(this).ApplyHideMethods(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.FakeAttributes)
                {
                    updateStatus("Injecting fake attributes...");
                    new FakeAttributesProtection(this).ApplyFakeAttributes(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.Watermark)
                {
                    updateStatus("Embedding watermark...");
                    new WatermarkProtection(this).ApplyWatermark(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.JunkCode)
                {
                    updateStatus("Generating junk code...");
                    new JunkCodeProtection(this).ApplyJunkCode(module, settings.JunkCount);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiDebug)
                {
                    updateStatus("Scattering anti-debug traps...");
                    new ScatterAntiDebugProtection(this).ScatterAntiDebugChecks(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiILDasm)
                {
                    updateStatus("Injecting anti-ILDasm traps...");
                    new AntiILDasmProtection(this).ApplyAntiILDasm(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.TokenConfusion)
                {
                    updateStatus("Injecting token confusion...");
                    new TokenConfusionProtection(this).ApplyTokenConfusion(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.StackUnderflow)
                {
                    updateStatus("Injecting stack underflow traps...");
                    new StackUnderflowProtection(this).ApplyStackUnderflow(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.DelegateEncryption)
                {
                    updateStatus("Encrypting delegate patterns...");
                    new DelegateEncryptionProtection(this).ApplyDelegateEncryption(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.InvalidMetadata)
                {
                    updateStatus("Injecting invalid metadata...");
                    new InvalidMetadataProtection(this).ApplyInvalidMetadata(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.BranchConfusion)
                {
                    updateStatus("Injecting branch confusion...");
                    new BranchConfusionProtection(this).ApplyBranchConfusion(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.TypeScrambler)
                {
                    updateStatus("Scrambling type hierarchies...");
                    new TypeScramblerProtection(this).ApplyTypeScrambler(module, modType);
                    new DecoyInjectorProtection(this).ApplyDecoyInjection(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.AntiMemoryDump)
                {
                    updateStatus("Injecting anti-memory-dump traps...");
                    new AntiMemoryDumpProtection(this).ApplyAntiMemoryDump(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.CodeVirtualization)
                {
                    updateStatus("Injecting code virtualization structures...");
                    new CodeVirtualizationProtection(this).ApplyCodeVirtualization(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.StringEncryption)
                {
                    updateStatus("Encrypting strings in injected methods...");
                    new StringEncryptionProtection(this).ApplyLateStringEncryption(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.EntryPointMover)
                {
                    updateStatus("Building entry-point trampoline chain...");
                    new EntryPointMoverProtection(this).ApplyEntryPointMover(module, modType);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.EnableRenamer)
                {
                    updateStatus("Remapping injected decoys...");
                    new RenamerProtection(this).ApplyLateInjectedRemap(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.DecompilerPoison)
                {
                    updateStatus("Poisoning decompilers (unreachable stack-underflow tails)...");
                    new DecompilerPoisonProtection(this).ApplyDecompilerPoison(module);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.DecompilerPoison && settings.RuntimeEncryption)
                {
                    updateStatus("Appending stack-trap to body-vault stubs...");
                    try { new BodyVaultProtection(this).ApplyLatePoison(module); }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.MergeLibraries && settings.LibrariesToMerge != null && settings.LibrariesToMerge.Count > 0)
                {
                    updateStatus("Merging libraries...");
                    new LibraryMergingProtection(this).ApplyLibraryMerging(module, modType, settings.LibrariesToMerge);
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.ExportCodeToDll)
                {
                    string _dllName = string.IsNullOrEmpty(settings.CodeDllName)
                        ? "MasonCore.dll" : settings.CodeDllName;

                    updateStatus("Moving encrypted function bodies into " + _dllName + "...");
                    try
                    {
                        int moved = new CodeExportToDllProtection(this)
                            .Apply(module, outputPath, _dllName);
                        if (moved > 0) updateStatus("Moved " + moved + " encrypted function bodies to " + _dllName + ".");
                    }
                    catch (Exception ex)
                    {
                        updateStatus("ExportCodeToDll move failed: " + ex.Message);
                    }

                    updateStatus("Hiding resources into " + _dllName + "...");
                    try
                    {
                        int added = new CodeExportToDllProtection(this)
                            .AppendResourcesToExistingDll(module, outputPath, _dllName);
                        if (added > 0) updateStatus("Moved " + added + " resources to " + _dllName + ".");
                    }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.TypeScrambler)
                {
                    updateStatus("Polymorphic noise injection...");
                    try { new PolymorphicNoiseProtection(this).ApplyPolymorphicNoise(module, modType); }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (settings.HideDesignerCode)
                {
                    updateStatus("Hiding designer-generated methods...");
                    try
                    {
                        int n = new DesignerHiderProtection(this).ApplyDesignerHider(module);
                        if (n > 0) updateStatus("Hid " + n + " designer methods (renamed + attrs stripped).");
                    }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                updateProgress(++currentStep * 100 / totalSteps);

                updateStatus("Scrambling module init chokepoint...");
                try
                {
                    int wrapped = new CctorScramblerProtection(this).ApplyCctorScrambler(module);
                    if (wrapped > 0) updateStatus("Opaque-wrapped " + wrapped + " cctor init calls.");
                }
                catch { }
                updateProgress(++currentStep * 100 / totalSteps);

                updateStatus("Corrupting metadata...");
                if (!settings.ExportCodeToDll)
                {
                    try { new MetadataConfusionProtection(this).ApplyMetadataConfusion(module); }
                    catch { }
                }
                updateProgress(++currentStep * 100 / totalSteps);

                if (cfg.MaximumEncryption)
                {
                    updateStatus("Maximum Encryption: amplifying integer chains...");
                    try { new MaximumEncryptionAmplifierProtection(this).ApplyMaximumAmplifier(module); }
                    catch { }
                }

                updateStatus("Writing protected assembly...");
                SaveModule(module, outputPath);

                updateProgress(100);
                updateStatus("Done!");
            }
            catch (Exception ex)
            {

                try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch { }
                throw new Exception("Protection failed at: " + ex.Message, ex);
            }
        }

        private void ResolveConflicts(ProtectionSettings s, PreAnalysis.AnalysisResult ar)
        {
            if (s.VMObfuscation && s.CalliConversion)
                s.CalliConversion = false;
        }

        private HashSet<string> _issuedPhraseNamesObf = new HashSet<string>(StringComparer.Ordinal);

        internal string MakeName(int length = -1)
        {

            if (cfg != null && cfg.MaximumEncryption)
                return GenerateStyledName(rng.Next(50, 91), false);
            if (cfg != null && cfg.HiddenRename)
                return MakePhraseName();
            if (length == -1)
                length = cfg != null ? cfg.RenameLength : 12;
            return GenerateStyledName(length, false);
        }

        internal string MakeJunkName(int length)
        {
            if (cfg != null && cfg.MaximumEncryption)
                return GenerateStyledName(rng.Next(50, 91), false);
            if (cfg != null && cfg.HiddenRename)
                return MakePhraseName();
            return GenerateStyledName(length, false);
        }

        private string MakePhraseName()
        {
            var words = RenamerProtection.LoadPhraseWordsInternal();
            if (words == null || words.Length < 2)
            {
                int len = cfg != null ? cfg.RenameLength : 12;
                if (len < 4) len = 4;
                return GenerateStyledName(len, false);
            }
            for (int attempt = 0; attempt < 12; attempt++)
            {
                int parts = rng.Next(2, 5);
                var sb = new System.Text.StringBuilder();
                for (int i = 0; i < parts; i++)
                    sb.Append(words[rng.Next(words.Length)]);
                string cand = sb.ToString();
                if (cand.Length > 64) cand = cand.Substring(0, 64);
                if (_issuedPhraseNamesObf.Add(cand)) return cand;
            }
            string fb;
            int tries = 0;
            do
            {
                int parts2 = rng.Next(2, 5);
                var sb2 = new System.Text.StringBuilder();
                for (int i = 0; i < parts2; i++)
                    sb2.Append(words[rng.Next(words.Length)]);
                sb2.Append(rng.Next(100, 99999).ToString());
                fb = sb2.ToString();
                if (fb.Length > 80) fb = fb.Substring(0, 80);
                tries++;
            } while (!_issuedPhraseNamesObf.Add(fb) && tries < 16);
            return fb;
        }

        internal string GenerateStyledName(int length, bool forceLatin)
        {
            if (length < 4) length = 4;
            nameCounter++;
            string pfx = cfg != null && !string.IsNullOrEmpty(cfg.RenamePrefix)
                            ? cfg.RenamePrefix
                            : "";

            bool userCharsetIsAscii = cfg != null && !string.IsNullOrEmpty(cfg.RandomChars)
                && IsAsciiCharset(cfg.RandomChars);
            int style = (forceLatin || userCharsetIsAscii) ? 0 : nameStyle;
            string body;
            switch (style)
            {
                case 1:  body = BuildConfusableName(length); break;
                case 2:  body = BuildMixedUnicodeName(length); break;
                case 3:  body = BuildInvisibleName(length); break;
                default: body = BuildLatinName(length); break;
            }

            int suffix;
            do
            {
                suffix = rng.Next(1000, 9999999);
            }
            while (!issuedNameSuffixes.Add(suffix));

            return pfx + body + suffix;
        }

        private static bool IsAsciiCharset(string s)
        {
            for (int i = 0; i < s.Length; i++)
                if (s[i] > 0x7F) return false;
            return true;
        }

        private string BuildLatinName(int length)
        {
            char[] buf = new char[length];
            for (int i = 0; i < length; i++)
                buf[i] = charset[rng.Next(charset.Length)];
            return new string(buf);
        }

        private static readonly char[] confusableChars = new char[]
        {
            '\u0430','\u0435','\u043E','\u0440','\u0441',
            '\u0443','\u0445','\u0456','\u0458','\u04BB',
            'a','e','o','p','c','u','x','i','j',
        };
        private string BuildConfusableName(int length)
        {
            char[] buf = new char[length];
            for (int i = 0; i < length; i++)
                buf[i] = confusableChars[rng.Next(confusableChars.Length)];
            return new string(buf);
        }

        private string BuildMixedUnicodeName(int length)
        {
            if (poly != null)
                return new string(poly.GenerateUnicodeName(length));
            return BuildLatinName(length);
        }

        private static readonly int[] invisibleCodePoints = new int[]
        {
            0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,
        };
        private string BuildInvisibleName(int length)
        {
            var sb = new StringBuilder(length + 1);
            sb.Append('_');
            for (int i = 0; i < length; i++)
                sb.Append((char)invisibleCodePoints[rng.Next(invisibleCodePoints.Length)]);
            return sb.ToString();
        }

        internal bool IsCompilerGenerated(TypeDef type)
        {
            if (type.IsGlobalModuleType) return true;
            if (type.Name == "<Module>") return true;
            string n = type.Name;
            if (n.StartsWith("<PrivateImplementationDetails>")) return true;
            if (n.StartsWith("__StaticArrayInit")) return true;
            if (n.Contains("__DisplayClass")) return true;
            if (n.Contains("<>c")) return true;
            if (n.StartsWith("<") && n.Contains(">")) return true;
            if (n.Contains("$StateMachine") || n.StartsWith("VB$")) return true;
            if (injectedTypes.Contains(type)) return true;

            if (type.DeclaringType != null && IsCompilerGenerated(type.DeclaringType)) return true;
            if (IsVBInfrastructure(type)) return true;
            foreach (var ca in type.CustomAttributes)
            {
                if (ca.AttributeType != null &&
                    ca.AttributeType.FullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute")
                    return true;
            }
            return false;
        }

        internal bool IsVBInfrastructure(TypeDef type)
        {
            if (type == null) return false;

            for (TypeDef cur = type; cur != null; cur = cur.DeclaringType)
            {
                string name = cur.Name;
                if (name == "MyProject" || name == "ThreadSafeObjectProvider`1")
                    return true;
                if (cur.HasCustomAttributes)
                {
                    foreach (var ca in cur.CustomAttributes)
                    {
                        if (ca.AttributeType == null) continue;
                        string af = ca.AttributeType.FullName;
                        if (af == "Microsoft.VisualBasic.MyGroupCollectionAttribute")
                            return true;
                        if (af == "Microsoft.VisualBasic.HideModuleNameAttribute")
                            return true;
                    }
                }
            }
            return false;
        }

        internal bool IsWinFormsType(TypeDef type)
        {
            if (type == null) return false;
            var current = type.BaseType;
            while (current != null)
            {
                string baseName = current.FullName;
                if (baseName != null)
                {
                    if (baseName.StartsWith("System.Windows.Forms."))
                        return true;
                    if (baseName == "Microsoft.VisualBasic.ApplicationServices.WindowsFormsApplicationBase" ||
                        baseName == "Microsoft.VisualBasic.ApplicationServices.ApplicationBase" ||
                        baseName == "Microsoft.VisualBasic.ApplicationServices.ConsoleApplicationBase")
                        return true;
                }
                TypeDef resolved = current.ResolveTypeDef();
                if (resolved == null) break;
                current = resolved.BaseType;
            }
            return false;
        }

        internal bool IsCompilerInfrastructureCall(IMethod method)
        {
            if (method == null) return false;
            var declType = method.DeclaringType;
            if (declType == null) return false;
            string fullName = declType.FullName;
            if (fullName == null) return false;
            if (fullName.StartsWith("System.Runtime.CompilerServices")) return true;
            if (fullName.StartsWith("System.Threading.Tasks.TaskAwaiter")) return true;
            if (fullName.StartsWith("System.Threading.Tasks.ValueTask")) return true;
            if (fullName == "System.Threading.Tasks.Task" && method.Name == "Yield") return true;
            return false;
        }

        internal bool MethodHasAsyncOrIteratorAttribute(MethodDef method)
        {
            if (method == null || !method.HasCustomAttributes) return false;
            foreach (var ca in method.CustomAttributes)
            {
                if (ca.AttributeType == null) continue;
                string fn = ca.AttributeType.FullName;
                if (fn == "System.Runtime.CompilerServices.AsyncStateMachineAttribute") return true;
                if (fn == "System.Runtime.CompilerServices.IteratorStateMachineAttribute") return true;
                if (fn == "System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute") return true;
            }
            return false;
        }

        internal bool IsConfirmedReferenceTypeCtor(ITypeDefOrRef declType)
        {
            if (declType == null) return false;

            var td = declType as TypeDef;
            if (td != null)
                return !td.IsValueType && !td.IsEnum;

            var tr = declType as TypeRef;
            if (tr != null)
            {
                try
                {
                    var resolved = tr.Resolve();
                    if (resolved != null)
                        return !resolved.IsValueType && !resolved.IsEnum;
                }
                catch { }

                string ns = tr.Namespace;
                string nm = tr.Name;

                if (ns == "System.Windows.Forms" &&
                    (nm == "Padding" || nm == "Message" || nm == "TableLayoutPanelCellPosition"))
                    return false;
                if (ns == "System.Drawing" &&
                    (nm == "Point" || nm == "PointF" ||
                     nm == "Size"  || nm == "SizeF"  ||
                     nm == "Rectangle" || nm == "RectangleF" ||
                     nm == "Color" || nm == "CharacterRange"))
                    return false;
                if (ns == "System" &&
                    (nm == "Int32" || nm == "Int64" || nm == "Int16" ||
                     nm == "UInt32" || nm == "UInt64" || nm == "UInt16" ||
                     nm == "Byte" || nm == "SByte" ||
                     nm == "Boolean" || nm == "Char" ||
                     nm == "Double" || nm == "Single" || nm == "Decimal" ||
                     nm == "IntPtr" || nm == "UIntPtr" ||
                     nm == "DateTime" || nm == "DateTimeOffset" ||
                     nm == "TimeSpan" || nm == "Guid" ||
                     nm == "Nullable`1" || nm == "ValueTuple"))
                    return false;
                if ((ns == "System.Drawing.Imaging") ||
                    (ns == "System.Drawing.Drawing2D"))
                    return false;

                return false;
            }

            return false;
        }

        internal bool CanProcessMethod(MethodDef m)
        {
            return CanProcessMethod(m, false);
        }

        internal bool CanProcessMethod(MethodDef m, bool allowDesigner)
        {
            if (m == null) return false;
            if (!m.HasBody || !m.Body.HasInstructions) return false;
            if (injectedMethods.Contains(m)) return false;

            if (IsMethodUserExcluded(m)) return false;

            bool isStub = bodyVaultedStubs.Contains(m);

            if (!isStub && !allowDesigner)
            {
                if (m.DeclaringType != null && IsCompilerGenerated(m.DeclaringType)) return false;
                if (m.DeclaringType != null && IsWinFormsType(m.DeclaringType)) return false;
                if (m.Name == "InitializeComponent") return false;
                if (m.CustomAttributes != null)
                {
                    foreach (var ca in m.CustomAttributes)
                    {
                        if (ca.AttributeType == null) continue;
                        string fn = ca.AttributeType.FullName;
                        if (fn == "System.Runtime.CompilerServices.CompilerGeneratedAttribute") return false;
                    }
                }
            }
            else if (!isStub && allowDesigner)
            {

                if (m.DeclaringType != null && IsCompilerGenerated(m.DeclaringType)) return false;
            }

            if (m.DeclaringType != null && m.DeclaringType.HasGenericParameters) return false;
            if (m.HasGenericParameters) return false;
            if (m.Name == "Create__Instance__" || m.Name == "Dispose__Instance__") return false;
            if (m.Name.StartsWith("<")) return false;
            if (m.Name.StartsWith("VB$")) return false;
            if (m.IsRuntimeSpecialName) return false;
            if (MethodHasAsyncOrIteratorAttribute(m)) return false;
            return true;
        }

        internal byte[] DeriveKeyPBKDF2(byte[] password, byte[] salt, int iterations, int keyLength)
        {

            try
            {
                using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
                    return kdf.GetBytes(keyLength);
            }
            catch (System.MissingMethodException)
            {

                using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations))
                    return kdf.GetBytes(keyLength);
            }
        }

        internal byte[] DeriveKeySHA(byte[] master, byte[] salt, int len)
        {

            byte[] prk;
            using (var hExtract = new HMACSHA256(salt))
                prk = hExtract.ComputeHash(master);

            byte[] result = new byte[len];
            byte[] prev = new byte[0];
            int produced = 0;
            byte counter = 1;
            using (var hExpand = new HMACSHA256(prk))
            {
                while (produced < len)
                {
                    byte[] input = new byte[prev.Length + 1];
                    Buffer.BlockCopy(prev, 0, input, 0, prev.Length);
                    input[input.Length - 1] = counter++;
                    byte[] block = hExpand.ComputeHash(input);
                    int take = Math.Min(block.Length, len - produced);
                    Buffer.BlockCopy(block, 0, result, produced, take);
                    produced += take;
                    prev = block;
                }
            }
            Array.Clear(prk, 0, prk.Length);
            return result;
        }

        internal byte[] CryptoRandom(int length)
        {
            byte[] buf = new byte[length];
            using (var csp = new RNGCryptoServiceProvider())
                csp.GetBytes(buf);
            return buf;
        }

        internal int ExtractInt(Instruction inst)
        {
            if (inst.OpCode == DnOpCodes.Ldc_I4) return (int)inst.Operand;
            if (inst.OpCode == DnOpCodes.Ldc_I4_S) return (sbyte)inst.Operand;
            if (inst.OpCode == DnOpCodes.Ldc_I4_0) return 0;
            if (inst.OpCode == DnOpCodes.Ldc_I4_1) return 1;
            if (inst.OpCode == DnOpCodes.Ldc_I4_2) return 2;
            if (inst.OpCode == DnOpCodes.Ldc_I4_3) return 3;
            if (inst.OpCode == DnOpCodes.Ldc_I4_4) return 4;
            if (inst.OpCode == DnOpCodes.Ldc_I4_5) return 5;
            if (inst.OpCode == DnOpCodes.Ldc_I4_6) return 6;
            if (inst.OpCode == DnOpCodes.Ldc_I4_7) return 7;
            if (inst.OpCode == DnOpCodes.Ldc_I4_8) return 8;
            if (inst.OpCode == DnOpCodes.Ldc_I4_M1) return -1;
            return int.MinValue;
        }

        internal bool IsIntLoad(Instruction inst)
        {
            return inst.OpCode == DnOpCodes.Ldc_I4 || inst.OpCode == DnOpCodes.Ldc_I4_S ||
                   inst.OpCode == DnOpCodes.Ldc_I4_0 || inst.OpCode == DnOpCodes.Ldc_I4_1 ||
                   inst.OpCode == DnOpCodes.Ldc_I4_2 || inst.OpCode == DnOpCodes.Ldc_I4_3 ||
                   inst.OpCode == DnOpCodes.Ldc_I4_4 || inst.OpCode == DnOpCodes.Ldc_I4_5 ||
                   inst.OpCode == DnOpCodes.Ldc_I4_6 || inst.OpCode == DnOpCodes.Ldc_I4_7 ||
                   inst.OpCode == DnOpCodes.Ldc_I4_8 || inst.OpCode == DnOpCodes.Ldc_I4_M1;
        }

        internal Instruction LoadInt(int value)
        {
            switch (value)
            {
                case -1: return Instruction.Create(DnOpCodes.Ldc_I4_M1);
                case 0: return Instruction.Create(DnOpCodes.Ldc_I4_0);
                case 1: return Instruction.Create(DnOpCodes.Ldc_I4_1);
                case 2: return Instruction.Create(DnOpCodes.Ldc_I4_2);
                case 3: return Instruction.Create(DnOpCodes.Ldc_I4_3);
                case 4: return Instruction.Create(DnOpCodes.Ldc_I4_4);
                case 5: return Instruction.Create(DnOpCodes.Ldc_I4_5);
                case 6: return Instruction.Create(DnOpCodes.Ldc_I4_6);
                case 7: return Instruction.Create(DnOpCodes.Ldc_I4_7);
                case 8: return Instruction.Create(DnOpCodes.Ldc_I4_8);
                default:
                    if (value >= -128 && value <= 127)
                        return Instruction.Create(DnOpCodes.Ldc_I4_S, (sbyte)value);
                    return Instruction.Create(DnOpCodes.Ldc_I4, value);
            }
        }

        internal List<int> FindSafeInsertPositions(IList<Instruction> il, IList<ExceptionHandler> ehs)
        {
            var positions = new List<int>();
            if (il == null || il.Count < 2) return positions;

            var forbidden = new HashSet<Instruction>();
            for (int i = 0; i < il.Count; i++)
            {
                var op = il[i].OpCode;
                if (op.OperandType == OperandType.InlineBrTarget ||
                    op.OperandType == OperandType.ShortInlineBrTarget)
                {
                    var t = il[i].Operand as Instruction;
                    if (t != null) forbidden.Add(t);
                }
                else if (op.OperandType == OperandType.InlineSwitch)
                {
                    var ts = il[i].Operand as Instruction[];
                    if (ts != null)
                        foreach (var t in ts) if (t != null) forbidden.Add(t);
                }
            }
            if (ehs != null)
            {
                foreach (var eh in ehs)
                {
                    if (eh.TryStart     != null) forbidden.Add(eh.TryStart);
                    if (eh.TryEnd       != null) forbidden.Add(eh.TryEnd);
                    if (eh.HandlerStart != null) forbidden.Add(eh.HandlerStart);
                    if (eh.HandlerEnd   != null) forbidden.Add(eh.HandlerEnd);
                    if (eh.FilterStart  != null) forbidden.Add(eh.FilterStart);
                }
            }

            for (int i = 1; i < il.Count; i++)
            {
                var cur = il[i];
                if (cur.OpCode == DnOpCodes.Ret ||
                    cur.OpCode == DnOpCodes.Throw ||
                    cur.OpCode == DnOpCodes.Rethrow) continue;
                if (cur.OpCode.FlowControl == FlowControl.Branch ||
                    cur.OpCode.FlowControl == FlowControl.Cond_Branch) continue;
                if (forbidden.Contains(cur)) continue;

                var prev = il[i - 1];
                if (!LeavesStackAtBaseline(prev)) continue;

                var pc = prev.OpCode.Code;
                if (pc == Code.Constrained || pc == Code.Volatile ||
                    pc == Code.Unaligned   || pc == Code.Readonly ||
                    pc == Code.Tailcall    || pc == Code.No) continue;

                if ((pc == Code.Ldftn || pc == Code.Ldvirtftn) &&
                    cur.OpCode.Code == Code.Newobj) continue;

                positions.Add(i);
            }
            return positions;
        }

        internal bool LeavesStackAtBaseline(Instruction inst)
        {
            if (inst == null) return false;
            switch (inst.OpCode.Code)
            {
                case Code.Nop:
                case Code.Pop:
                case Code.Stloc:
                case Code.Stloc_S:
                case Code.Stloc_0:
                case Code.Stloc_1:
                case Code.Stloc_2:
                case Code.Stloc_3:
                case Code.Stsfld:
                case Code.Stfld:
                case Code.Stelem:
                case Code.Stelem_I:
                case Code.Stelem_I1:
                case Code.Stelem_I2:
                case Code.Stelem_I4:
                case Code.Stelem_I8:
                case Code.Stelem_R4:
                case Code.Stelem_R8:
                case Code.Stelem_Ref:
                case Code.Stind_I:
                case Code.Stind_I1:
                case Code.Stind_I2:
                case Code.Stind_I4:
                case Code.Stind_I8:
                case Code.Stind_R4:
                case Code.Stind_R8:
                case Code.Stind_Ref:
                case Code.Starg:
                case Code.Starg_S:
                case Code.Stobj:
                    return true;
                case Code.Call:
                case Code.Callvirt:
                {
                    var m = inst.Operand as IMethod;
                    if (m == null || m.MethodSig == null) return false;
                    var rt = m.MethodSig.RetType;
                    return rt != null && rt.FullName == "System.Void";
                }
            }
            return false;
        }

        internal void InjectCallInCctor(ModuleDef module, TypeDef owner, MethodDef target)
        {
            var cctor = owner.FindStaticConstructor();
            if (cctor == null)
            {
                cctor = new MethodDefUser(".cctor",
                    MethodSig.CreateStatic(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                    DnMethodAttributes.RTSpecialName);
                cctor.Body = new CilBody();
                cctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                owner.Methods.Add(cctor);
            }

            var il = cctor.Body.Instructions;
            int insertAt = 0;
            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode == DnOpCodes.Ret) { insertAt = i; break; }
            }
            il.Insert(insertAt, Instruction.Create(DnOpCodes.Call, target));
        }

        internal void InjectCallInRandomMethods(ModuleDef module, MethodDef target, int minCount, int maxCount)
        {
            if (target == null || target.MethodSig == null) return;
            if (target.MethodSig.Params.Count != 0) return;
            if (target.MethodSig.RetType != null && target.MethodSig.RetType.FullName != "System.Void") return;

            var candidates = new List<MethodDef>();
            foreach (var t in module.GetTypes())
            {
                if (t == null) continue;
                if (IsCompilerGenerated(t)) continue;
                if (injectedTypes.Contains(t)) continue;
                if (t.HasGenericParameters) continue;
                foreach (var m in t.Methods)
                {
                    if (m == null || !m.HasBody) continue;
                    if (injectedMethods.Contains(m)) continue;
                    if (m == target) continue;
                    if (m.HasGenericParameters) continue;
                    if (m.IsRuntimeSpecialName && !m.IsStaticConstructor && !m.IsConstructor) continue;
                    if (m.IsPinvokeImpl) continue;
                    if (m.IsStaticConstructor) continue;
                    if (!m.Body.HasInstructions) continue;
                    if (m.Body.Instructions.Count < 4) continue;
                    if (m.Body.Instructions.Count > 8000) continue;
                    if (m.Body.HasExceptionHandlers) continue;
                    if (MethodHasAsyncOrIteratorAttribute(m)) continue;
                    if (m.Name == "InitializeComponent") continue;
                    if (m.DeclaringType != null && IsWinFormsType(m.DeclaringType)) continue;
                    candidates.Add(m);
                }
            }
            if (candidates.Count == 0) return;

            int want = rng.Next(minCount, maxCount + 1);
            if (want > candidates.Count) want = candidates.Count;

            for (int i = candidates.Count - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                var tmp = candidates[i]; candidates[i] = candidates[j]; candidates[j] = tmp;
            }

            for (int k = 0; k < want; k++)
            {
                var host = candidates[k];
                try
                {
                    var il = host.Body.Instructions;
                    int safeMax = Math.Min(il.Count, 16);
                    int insertAt = rng.Next(0, safeMax);
                    il.Insert(insertAt, Instruction.Create(DnOpCodes.Call, target));
                }
                catch { }
            }
        }

        internal NativeShroud EnsureShroud(ModuleDef module)
        {
            if (antiShroud != null) return antiShroud;
            TypeDef container = new TypeDefUser("", MakeName(),
                module.CorLibTypes.Object.TypeDefOrRef);
            container.Attributes = DnTypeAttributes.NotPublic | DnTypeAttributes.Abstract |
                DnTypeAttributes.Sealed | DnTypeAttributes.BeforeFieldInit;
            module.Types.Add(container);
            injectedTypes.Add(container);
            antiShroud = new NativeShroud(this, module, container);
            antiShroud.Build();
            return antiShroud;
        }

        internal void InjectCallAtTop(ModuleDef module, TypeDef owner, MethodDef target)
        {
            var cctor = owner.FindStaticConstructor();
            if (cctor == null)
            {
                cctor = new MethodDefUser(".cctor",
                    MethodSig.CreateStatic(module.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                    DnMethodAttributes.RTSpecialName);
                cctor.Body = new CilBody();
                cctor.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
                owner.Methods.Add(cctor);
            }

            cctor.Body.Instructions.Insert(0, Instruction.Create(DnOpCodes.Call, target));
        }

        private void SaveModule(ModuleDef module, string outputPath)
        {
            foreach (TypeDef type in module.GetTypes())
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody && method.Body.HasInstructions)
                    {
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
                }
            }

            var writerOpts = new ModuleWriterOptions(module as ModuleDefMD);
            writerOpts.MetadataOptions.Flags = (MetadataFlags)0;
            writerOpts.Logger = DummyLogger.NoThrowInstance;

            (module as ModuleDefMD).Write(outputPath, writerOpts);
        }
    }
}

