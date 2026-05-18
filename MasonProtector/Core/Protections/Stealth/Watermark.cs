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
    internal class WatermarkProtection
    {
        private Obfuscation engine;
        private Random rng;

        internal WatermarkProtection(Obfuscation eng)
        {
            engine = eng;
            rng = eng.rng;
        }

        internal void ApplyWatermark(ModuleDef module)
        {
            byte[] stamp = engine.CryptoRandom(16);
            long timestamp = DateTime.UtcNow.ToBinary();
            byte[] tsBytes = BitConverter.GetBytes(timestamp);

            byte[] watermarkData = new byte[stamp.Length + tsBytes.Length + 4];
            Buffer.BlockCopy(stamp, 0, watermarkData, 0, stamp.Length);
            Buffer.BlockCopy(tsBytes, 0, watermarkData, stamp.Length, tsBytes.Length);
            byte[] tailRandom = engine.CryptoRandom(4);
            Buffer.BlockCopy(tailRandom, 0, watermarkData, watermarkData.Length - 4, 4);

            byte wmKey = (byte)rng.Next(1, 255);
            for (int i = 0; i < watermarkData.Length; i++)
                watermarkData[i] ^= wmKey;

            module.Resources.Add(new EmbeddedResource(engine.MakeName(), watermarkData));

            var modType = module.Types.FirstOrDefault(t => t.Name == "<Module>");
            if (modType != null)
            {
                var wmField = new FieldDefUser(engine.MakeName(),
                    new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                    DnFieldAttributes.Private | DnFieldAttributes.Static);
                modType.Fields.Add(wmField);
            }

            for (int i = 0; i < 12; i++)
            {
                byte[] chunk = new byte[rng.Next(4, 12)];
                Buffer.BlockCopy(watermarkData, 0, chunk, 0, Math.Min(chunk.Length, watermarkData.Length));
                for (int j = 0; j < chunk.Length; j++)
                    chunk[j] ^= (byte)rng.Next(0, 255);

                TypeDef fakeType = null;
                foreach (var t in module.Types)
                {
                    if (engine.injectedTypes.Contains(t)) { fakeType = t; break; }
                }
                if (fakeType == null) fakeType = modType;
                if (fakeType != null)
                {
                    fakeType.Fields.Add(new FieldDefUser(engine.MakeName(),
                        new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
                        DnFieldAttributes.Private | DnFieldAttributes.Static));
                }
            }
        }
    }
}

