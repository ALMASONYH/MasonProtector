using System;
using System.Collections.Generic;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

using DnFieldAttributes = dnlib.DotNet.FieldAttributes;
using DnMethodAttributes = dnlib.DotNet.MethodAttributes;
using DnMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class AntiCrackProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal MethodDef OnDetectionMethod { get; private set; }
        internal TypeDef   HelperType        { get; private set; }

        internal AntiCrackProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void Apply(ModuleDef userModule, TypeDef modType, ProtectionSettings s)
        {
            if (!s.AntiCrack) return;

            string protectorPath = typeof(AntiCrackProtection).Assembly.Location;
            ModuleDefMD srcModule = ModuleDefMD.Load(protectorPath);
            TypeDef srcHelper = srcModule.Find(
                "MasonProtector.Core.RuntimeStubs.AntiCrackRuntime", false);
            if (srcHelper == null) return;

            var cloner = new TypeCloner(srcModule, userModule);
            string helperName = engine.MakeName();
            TypeDef dst = cloner.CloneType(srcHelper, "", helperName);

            RegisterAllNested(dst, engine);

            FieldDef fSub        = dst.FindField("_registrySubKey");
            FieldDef fVal        = dst.FindField("_registryValueName");
            FieldDef fMax        = dst.FindField("_maxAttempts");
            FieldDef fMbSender   = dst.FindField("_msgBoxSender");
            FieldDef fMbText     = dst.FindField("_msgBoxText");
            FieldDef fMbAttempt  = dst.FindField("_msgBoxAttempt");
            FieldDef fWhUrl      = dst.FindField("_webhookUrl");
            FieldDef fWhAttempt  = dst.FindField("_webhookAttempt");
            FieldDef fWhSshot    = dst.FindField("_webhookScreenshot");
            FieldDef fWhSysinfo  = dst.FindField("_webhookSysInfo");
            FieldDef fRfUrl      = dst.FindField("_remoteFileUrl");
            FieldDef fRfAttempt  = dst.FindField("_remoteFileAttempt");
            FieldDef fSdAttempt  = dst.FindField("_selfDestructAttempt");
            MethodDef mOnDetect  = dst.FindMethod("OnDetection");

            MethodDef mDecodeStr = dst.FindMethod("DecodeStr");
            if (fSub == null || fVal == null || fMax == null ||
                fMbSender == null || fMbText == null || fMbAttempt == null ||
                fWhUrl == null || fWhAttempt == null ||
                fWhSshot == null || fWhSysinfo == null ||
                fRfUrl == null || fRfAttempt == null ||
                fSdAttempt == null ||
                mOnDetect == null || mDecodeStr == null)
                return;

            string subKey =
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\" +
                engine.MakeName(rng.Next(6, 12)) + "\\" + engine.MakeName(rng.Next(6, 12));
            string valName = engine.MakeName(rng.Next(4, 10));

            int msgAttempt    = s.AntiCrackMessageBox    ? Clamp(s.AntiCrackMessageBoxAttempt,    1, 500) : 0;
            int webAttempt    = s.AntiCrackWebhook       ? Clamp(s.AntiCrackWebhookAttempt,       1, 500) : 0;
            int remoteAttempt = s.AntiCrackRemoteFile    ? Clamp(s.AntiCrackRemoteFileAttempt,    1, 500) : 0;
            int sdAttempt     = s.AntiCrackSelfDestruct  ? Clamp(s.AntiCrackSelfDestructAttempt,  1, 500) : 0;
            string msgSender  = s.AntiCrackMessageBox    ? (s.AntiCrackMessageBoxSender ?? "")            : "";
            string msgText    = s.AntiCrackMessageBox    ? (s.AntiCrackMessageBoxText   ?? "")            : "";
            string webUrl     = s.AntiCrackWebhook       ? (s.AntiCrackWebhookUrl       ?? "")            : "";
            string rfUrl      = s.AntiCrackRemoteFile    ? (s.AntiCrackRemoteFileUrl    ?? "")            : "";

            MethodDef cctor = dst.FindStaticConstructor();
            if (cctor == null)
            {
                cctor = new MethodDefUser(".cctor",
                    MethodSig.CreateStatic(userModule.CorLibTypes.Void),
                    DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                    DnMethodAttributes.Private | DnMethodAttributes.Static |
                    DnMethodAttributes.HideBySig | DnMethodAttributes.SpecialName |
                    DnMethodAttributes.RTSpecialName);
                cctor.Body = new CilBody();
                dst.Methods.Add(cctor);
                engine.injectedMethods.Add(cctor);
            }
            else
            {
                cctor.Body = new CilBody();
            }

            byte xorKey = (byte)rng.Next(1, 255);

            var il = cctor.Body.Instructions;
            EmitObfStr(il, subKey,    xorKey, mDecodeStr);  il.Add(Instruction.Create(DnOpCodes.Stsfld, fSub));
            EmitObfStr(il, valName,   xorKey, mDecodeStr);  il.Add(Instruction.Create(DnOpCodes.Stsfld, fVal));
            EmitLdcI4(il, 500);                              il.Add(Instruction.Create(DnOpCodes.Stsfld, fMax));
            EmitObfStr(il, msgSender, xorKey, mDecodeStr);  il.Add(Instruction.Create(DnOpCodes.Stsfld, fMbSender));
            EmitObfStr(il, msgText,   xorKey, mDecodeStr);  il.Add(Instruction.Create(DnOpCodes.Stsfld, fMbText));
            EmitLdcI4(il, msgAttempt);                       il.Add(Instruction.Create(DnOpCodes.Stsfld, fMbAttempt));
            EmitObfStr(il, webUrl,    xorKey, mDecodeStr);  il.Add(Instruction.Create(DnOpCodes.Stsfld, fWhUrl));
            EmitLdcI4(il, webAttempt);                       il.Add(Instruction.Create(DnOpCodes.Stsfld, fWhAttempt));
            EmitLdcI4(il, s.AntiCrackWebhook && s.AntiCrackWebhookScreenshot ? 1 : 0);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fWhSshot));
            EmitLdcI4(il, s.AntiCrackWebhook && s.AntiCrackWebhookSysInfo ? 1 : 0);
            il.Add(Instruction.Create(DnOpCodes.Stsfld, fWhSysinfo));
            EmitObfStr(il, rfUrl,     xorKey, mDecodeStr);  il.Add(Instruction.Create(DnOpCodes.Stsfld, fRfUrl));
            EmitLdcI4(il, remoteAttempt);                    il.Add(Instruction.Create(DnOpCodes.Stsfld, fRfAttempt));
            EmitLdcI4(il, sdAttempt);                        il.Add(Instruction.Create(DnOpCodes.Stsfld, fSdAttempt));
            il.Add(Instruction.Create(DnOpCodes.Ret));
            cctor.Body.KeepOldMaxStack = false;
            cctor.Body.MaxStack = 4;

            MethodDef initThunk = new MethodDefUser(engine.MakeName(),
                MethodSig.CreateStatic(userModule.CorLibTypes.Void),
                DnMethodImplAttributes.IL | DnMethodImplAttributes.Managed,
                DnMethodAttributes.Assembly | DnMethodAttributes.Static |
                DnMethodAttributes.HideBySig);
            initThunk.Body = new CilBody();
            initThunk.Body.Instructions.Add(Instruction.Create(DnOpCodes.Ret));
            dst.Methods.Add(initThunk);
            engine.injectedMethods.Add(initThunk);
            engine.InjectCallInCctor(userModule, modType, initThunk);

            foreach (FieldDef f in dst.Fields)
                f.Name = engine.MakeName();
            foreach (MethodDef m in dst.Methods)
            {
                if (m == cctor) continue;
                if (m.IsConstructor) continue;
                m.Name = engine.MakeName();
            }

            OnDetectionMethod = mOnDetect;
            HelperType        = dst;

            engine.lateStringEncryptionExcludedTypes.Add(dst);
        }

        private static void RegisterAllNested(TypeDef td, Obfuscation engine)
        {
            engine.injectedTypes.Add(td);
            foreach (MethodDef m in td.Methods) engine.injectedMethods.Add(m);
            foreach (TypeDef nt in td.NestedTypes) RegisterAllNested(nt, engine);
        }

        private static int Clamp(int v, int lo, int hi)
        {
            if (v < lo) return lo;
            if (v > hi) return hi;
            return v;
        }

        private static void EmitLdstr(IList<Instruction> il, string s)
        {
            if (s == null) s = "";
            il.Add(Instruction.Create(DnOpCodes.Ldstr, s));
        }

        private static void EmitObfStr(IList<Instruction> il, string s, byte xorKey, IMethod decodeStr)
        {
            if (string.IsNullOrEmpty(s))
            {
                il.Add(Instruction.Create(DnOpCodes.Ldstr, s ?? ""));
                return;
            }
            string enc = XorEncode(s, xorKey);
            il.Add(Instruction.Create(DnOpCodes.Ldstr, enc));
            EmitLdcI4(il, xorKey);
            il.Add(Instruction.Create(DnOpCodes.Call, decodeStr));
        }

        private static string XorEncode(string s, byte xorKey)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            char[] ch = s.ToCharArray();
            for (int i = 0; i < ch.Length; i++)
                ch[i] = (char)(ch[i] ^ (xorKey ^ (byte)(i & 0xFF)));
            return new string(ch);
        }

        private static void EmitLdcI4(IList<Instruction> il, int v)
        {
            switch (v)
            {
                case -1: il.Add(Instruction.Create(DnOpCodes.Ldc_I4_M1)); return;
                case 0:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));  return;
                case 1:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));  return;
                case 2:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));  return;
                case 3:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_3));  return;
                case 4:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_4));  return;
                case 5:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_5));  return;
                case 6:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_6));  return;
                case 7:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_7));  return;
                case 8:  il.Add(Instruction.Create(DnOpCodes.Ldc_I4_8));  return;
            }
            if (v >= -128 && v <= 127)
            {
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4_S, (sbyte)v));
                return;
            }
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, v));
        }
    }
}

