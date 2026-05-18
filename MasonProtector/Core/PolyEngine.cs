using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using dnlib.DotNet.Emit;

using DnOpCodes = dnlib.DotNet.Emit.OpCodes;

namespace MasonProtector.Core
{
    internal class PolyEngine
    {
        private Random rng;
        private byte[] buildFingerprint;
        private int variantSeed;

        private static readonly char[][] unicodeBlocks = new char[][]
        {
            "\u0400\u0401\u0402\u0403\u0404\u0405\u0406\u0407\u0408\u0409\u040A\u040B\u040C\u040D".ToCharArray(),
            "\u4E00\u4E01\u4E02\u4E03\u4E04\u4E05\u4E06\u4E07\u4E08\u4E09\u4E0A\u4E0B\u4E0C\u4E0D".ToCharArray(),
            "\u0621\u0622\u0623\u0624\u0625\u0626\u0627\u0628\u0629\u062A\u062B\u062C\u062D\u062E".ToCharArray(),
            "\uAC00\uAC01\uAC02\uAC03\uAC04\uAC05\uAC06\uAC07\uAC08\uAC09\uAC0A\uAC0B\uAC0C\uAC0D".ToCharArray(),
            "\u2200\u2201\u2202\u2203\u2204\u2205\u2206\u2207\u2208\u2209\u220A\u220B\u220C\u220D".ToCharArray(),
            "\u2500\u2501\u2502\u2503\u2504\u2505\u2506\u2507\u2508\u2509\u250A\u250B\u250C\u250D".ToCharArray(),
        };

        private static readonly string[] realisticVarPrefixes = new string[]
        {
            "handler", "ctx", "buf", "mgr", "svc", "proc", "idx",
            "ptr", "val", "ref", "obj", "src", "dst", "tmp",
            "node", "item", "elem", "slot", "seg", "blk",
            "cfg", "opt", "res", "req", "rsp", "tok",
        };

        internal PolyEngine(Random random)
        {
            rng = random;
            buildFingerprint = new byte[32];
            using (var csp = new RNGCryptoServiceProvider())
                csp.GetBytes(buildFingerprint);
            variantSeed = BitConverter.ToInt32(buildFingerprint, 0);
        }

        internal char[] GenerateUnicodeName(int length)
        {
            char[] name = new char[length];
            int blockCount = unicodeBlocks.Length;

            int primary = rng.Next(blockCount);
            int secondary = rng.Next(blockCount);
            while (secondary == primary) secondary = rng.Next(blockCount);

            for (int i = 0; i < length; i++)
            {
                int pick = (i % 3 == 0) ? secondary : primary;
                var block = unicodeBlocks[pick];
                name[i] = block[rng.Next(block.Length)];
            }

            return name;
        }

        internal string GenerateRealisticName()
        {
            string prefix = realisticVarPrefixes[rng.Next(realisticVarPrefixes.Length)];
            return prefix + rng.Next(10, 9999);
        }

        internal int SelectVariant(int maxVariants, int methodToken)
        {
            unchecked
            {
                int hash = variantSeed ^ methodToken ^ (int)DateTime.UtcNow.Ticks;
                hash = hash * 1540483477 + 0x4E67C6A7;
                return Math.Abs(hash) % maxVariants;
            }
        }

        internal List<Instruction> BuildIntExpression(int target)
        {
            int variant = rng.Next(0, 12);
            switch (variant)
            {
                case 0: return BuildXorChain(target);
                case 1: return BuildAddSubChain(target);
                case 2: return BuildNotXor(target);
                case 3: return BuildShiftMask(target);
                case 4: return BuildMulDivChain(target);
                case 5: return BuildTripleXor(target);
                case 6: return BuildBitRotate(target);
                case 7: return BuildPolynomial(target);
                case 8: return BuildNestedArith(target);
                case 9: return BuildAndOrChain(target);
                case 10: return BuildComplement(target);
                default: return BuildDoubleNot(target);
            }
        }

        private List<Instruction> BuildXorChain(int target)
        {
            var il = new List<Instruction>();
            int k = rng.Next(10000, int.MaxValue / 2);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ target));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            return il;
        }

        private List<Instruction> BuildAddSubChain(int target)
        {
            var il = new List<Instruction>();
            int a = rng.Next(100000, 9999999);
            int b = rng.Next(100000, 9999999);
            int c = target - a + b;
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, c));
            il.Add(Instruction.Create(DnOpCodes.Add));
            return il;
        }

        private List<Instruction> BuildNotXor(int target)
        {
            var il = new List<Instruction>();
            int k = rng.Next(int.MinValue, int.MaxValue);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (~k) ^ target));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            return il;
        }

        private List<Instruction> BuildShiftMask(int target)
        {
            var il = new List<Instruction>();
            int shift = rng.Next(1, 8);
            int shifted = target << shift;
            int noise = rng.Next(0, (1 << shift) - 1);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, shifted | noise));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, shift));
            il.Add(Instruction.Create(DnOpCodes.Shr));
            return il;
        }

        private List<Instruction> BuildMulDivChain(int target)
        {
            var il = new List<Instruction>();
            int mul = rng.Next(2, 50);
            int offset = rng.Next(1000, 99999);
            int product = target * mul + offset;
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, product));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, offset));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, mul));
            il.Add(Instruction.Create(DnOpCodes.Div));
            return il;
        }

        private List<Instruction> BuildTripleXor(int target)
        {
            var il = new List<Instruction>();
            int a = rng.Next(int.MinValue, int.MaxValue);
            int b = rng.Next(int.MinValue, int.MaxValue);
            int c = target ^ a ^ b;
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, c));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            return il;
        }

        private List<Instruction> BuildBitRotate(int target)
        {
            var il = new List<Instruction>();
            int rot = rng.Next(1, 16);
            uint utarget = (uint)target;
            uint rotated = (utarget >> rot) | (utarget << (32 - rot));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)rotated));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, rot));
            il.Add(Instruction.Create(DnOpCodes.Shl));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (int)rotated));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, 32 - rot));
            il.Add(Instruction.Create(DnOpCodes.Shr_Un));
            il.Add(Instruction.Create(DnOpCodes.Or));
            return il;
        }

        private List<Instruction> BuildPolynomial(int target)
        {
            var il = new List<Instruction>();
            int degree = rng.Next(2, 5);
            int x = rng.Next(2, 20);

            if (degree == 2)
            {
                int a = rng.Next(1, 30);
                int b = rng.Next(1, 30);
                int c = rng.Next(1, 30);
                int polyResult = a * x * x + b * x + c;
                int correction = target - polyResult;

                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Add));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, c));
                il.Add(Instruction.Create(DnOpCodes.Add));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                il.Add(Instruction.Create(DnOpCodes.Add));
            }
            else if (degree == 3)
            {
                int a = rng.Next(1, 10);
                int b = rng.Next(1, 10);
                int polyResult = a * x * x * x + b * x * x;
                int correction = target - polyResult;

                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Add));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                il.Add(Instruction.Create(DnOpCodes.Add));
            }
            else
            {
                int a = rng.Next(1, 5);
                int polyResult = a * x * x * x * x;
                int correction = target - polyResult;

                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                il.Add(Instruction.Create(DnOpCodes.Mul));
                il.Add(Instruction.Create(DnOpCodes.Ldc_I4, correction));
                il.Add(Instruction.Create(DnOpCodes.Add));
            }

            return il;
        }

        private List<Instruction> BuildNestedArith(int target)
        {
            var il = new List<Instruction>();
            int a = rng.Next(10000, 999999);
            int b = rng.Next(10000, 999999);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
            il.Add(Instruction.Create(DnOpCodes.Add));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, (a + b) - target));
            il.Add(Instruction.Create(DnOpCodes.Sub));
            return il;
        }

        private List<Instruction> BuildAndOrChain(int target)
        {
            var il = new List<Instruction>();
            int mask = rng.Next(int.MinValue, int.MaxValue);
            int part1 = target & mask;
            int part2 = target & ~mask;
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, part1));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, part2));
            il.Add(Instruction.Create(DnOpCodes.Or));
            return il;
        }

        private List<Instruction> BuildComplement(int target)
        {
            var il = new List<Instruction>();
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, ~target));
            il.Add(Instruction.Create(DnOpCodes.Not));
            return il;
        }

        private List<Instruction> BuildDoubleNot(int target)
        {
            var il = new List<Instruction>();
            int k = rng.Next(int.MinValue, int.MaxValue);
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Not));
            il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k ^ target));
            il.Add(Instruction.Create(DnOpCodes.Xor));
            return il;
        }

        internal byte[] GenerateAESKey()
        {
            return CryptoRand(32);
        }

        internal byte[] GenerateAESIV()
        {
            return CryptoRand(16);
        }

        internal byte[] GenerateXORKey(int length)
        {
            return CryptoRand(length);
        }

        internal int GenerateHMACKey()
        {
            return BitConverter.ToInt32(CryptoRand(4), 0);
        }

        private byte[] CryptoRand(int len)
        {
            byte[] buf = new byte[len];
            using (var csp = new RNGCryptoServiceProvider())
                csp.GetBytes(buf);
            return buf;
        }

        internal byte[] GetFingerprint()
        {
            return (byte[])buildFingerprint.Clone();
        }

        internal int PickControlFlowStrategy()
        {
            return rng.Next(0, 4);
        }

        internal int PickStringEncryptMode()
        {
            return rng.Next(0, 5);
        }

        internal int[] GenerateOpcodeMapping(int count)
        {
            int[] mapping = new int[count];
            for (int i = 0; i < count; i++)
                mapping[i] = i;

            for (int i = count - 1; i > 0; i--)
            {
                int j = rng.Next(0, i + 1);
                int tmp = mapping[i];
                mapping[i] = mapping[j];
                mapping[j] = tmp;
            }

            return mapping;
        }

        internal List<Instruction> GenerateOpaqueTrue()
        {
            var il = new List<Instruction>();
            int variant = rng.Next(0, 12);
            switch (variant)
            {
                case 0:
                    int x = rng.Next(2, 10000);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                    il.Add(Instruction.Create(DnOpCodes.Mul));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Clt));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 1:
                    int a = rng.Next(1, 100);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 2:
                    int n = rng.Next(100, 99999);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, n));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, n));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 3:
                    int v = rng.Next(2, 1000);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, v * v));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, v));
                    il.Add(Instruction.Create(DnOpCodes.Rem));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 4:
                    int p = rng.Next(1, 50);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, p));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, p));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 5:
                    int m = rng.Next(1, 10000);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, m | 1));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    break;

                case 6:
                    int q = rng.Next(2, 100);
                    int r = rng.Next(2, 100);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, q));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r));
                    il.Add(Instruction.Create(DnOpCodes.Or));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, q));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, r));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, q ^ r));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 7:
                    int w = rng.Next(3, 999);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, w));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, w));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, w));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    il.Add(Instruction.Create(DnOpCodes.Shl));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 8:
                    int g = rng.Next(10, 99999);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, g));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, g));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 9:
                    int h = rng.Next(2, 500);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, h));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, h));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, -1));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 10:
                    int k1 = rng.Next(100, 99999);
                    int k2 = rng.Next(100, 99999);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k1));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k2));
                    il.Add(Instruction.Create(DnOpCodes.Or));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k1));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k2));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k1));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, k2));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                default:
                    int s = rng.Next(2, 100);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, s));
                    il.Add(Instruction.Create(DnOpCodes.Neg));
                    il.Add(Instruction.Create(DnOpCodes.Neg));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, s));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;
            }
            return il;
        }

        internal List<Instruction> GenerateOpaqueFalse()
        {
            var il = new List<Instruction>();
            int variant = rng.Next(0, 8);
            switch (variant)
            {
                case 0:
                    int a = rng.Next(10, 9999);
                    int b = a + rng.Next(1, 100);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, a));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, b));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                case 1:
                    int x = rng.Next(1, 9999);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, x));
                    il.Add(Instruction.Create(DnOpCodes.Xor));
                    break;

                case 2:
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    break;

                case 3:
                    int n = rng.Next(2, 9999) * 2;
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, n));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_2));
                    il.Add(Instruction.Create(DnOpCodes.Rem));
                    break;

                case 4:
                    int c = rng.Next(10, 9999);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, c));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, c));
                    il.Add(Instruction.Create(DnOpCodes.And));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, c));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    break;

                case 5:
                    int d = rng.Next(2, 9999);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, d));
                    il.Add(Instruction.Create(DnOpCodes.Not));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, d));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_1));
                    il.Add(Instruction.Create(DnOpCodes.Add));
                    break;

                case 6:
                    int e = rng.Next(1, 999);
                    int f = e + rng.Next(1, 100);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, e));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, f));
                    il.Add(Instruction.Create(DnOpCodes.Clt));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4_0));
                    il.Add(Instruction.Create(DnOpCodes.Ceq));
                    break;

                default:
                    int g = rng.Next(100, 9999);
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, g));
                    il.Add(Instruction.Create(DnOpCodes.Ldc_I4, g));
                    il.Add(Instruction.Create(DnOpCodes.Sub));
                    break;
            }
            return il;
        }
    }
}

