using System.Runtime.InteropServices;

namespace Whois.Security.Internal;

/// <summary>
/// A field element in GF(2^255-19), represented as 10 limbs in base 2^25.5.
/// Limbs 0,2,4,6,8 are 26-bit; limbs 1,3,5,7,9 are 25-bit.
/// Based on the SUPERCOP ref10 representation used by Chaos.NaCl and RFC 8032.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FieldElement
{
    internal long H0;
    internal long H1;
    internal long H2;
    internal long H3;
    internal long H4;
    internal long H5;
    internal long H6;
    internal long H7;
    internal long H8;
    internal long H9;

    internal static readonly FieldElement Zero = default;

    internal static readonly FieldElement One = new FieldElement { H0 = 1 };

    // sqrt(-1) mod p, little-endian bytes
    internal static readonly FieldElement SqrtM1 = FromBytes(new byte[]
    {
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
        0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
        0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
        0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
    });

    // d = -121665/121666 mod p (little-endian)
    internal static readonly FieldElement D = FromBytes(new byte[]
    {
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
        0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
        0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
        0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
    });

    // 2*d
    internal static readonly FieldElement D2 = FromBytes(new byte[]
    {
        0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb,
        0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
        0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19,
        0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24,
    });

    internal static FieldElement FromBytes(ReadOnlySpan<byte> s)
    {
        long h0 = Load4(s, 0);
        long h1 = Load3(s, 4) << 6;
        long h2 = Load3(s, 7) << 5;
        long h3 = Load3(s, 10) << 3;
        long h4 = Load3(s, 13) << 2;
        long h5 = Load4(s, 16);
        long h6 = Load3(s, 20) << 7;
        long h7 = Load3(s, 23) << 5;
        long h8 = Load3(s, 26) << 4;
        long h9 = (Load3(s, 29) & 8388607) << 2;

        // Carry propagation order from Chaos.NaCl fe_frombytes (odd indices first, then even)
        long c9 = (h9 + (1L << 24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
        long c1 = (h1 + (1L << 24)) >> 25; h2 += c1; h1 -= c1 << 25;
        long c3 = (h3 + (1L << 24)) >> 25; h4 += c3; h3 -= c3 << 25;
        long c5 = (h5 + (1L << 24)) >> 25; h6 += c5; h5 -= c5 << 25;
        long c7 = (h7 + (1L << 24)) >> 25; h8 += c7; h7 -= c7 << 25;
        long c0 = (h0 + (1L << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
        long c2 = (h2 + (1L << 25)) >> 26; h3 += c2; h2 -= c2 << 26;
        long c4 = (h4 + (1L << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        long c6 = (h6 + (1L << 25)) >> 26; h7 += c6; h6 -= c6 << 26;
        long c8 = (h8 + (1L << 25)) >> 26; h9 += c8; h8 -= c8 << 26;

        return new FieldElement
        {
            H0 = h0,
            H1 = h1,
            H2 = h2,
            H3 = h3,
            H4 = h4,
            H5 = h5,
            H6 = h6,
            H7 = h7,
            H8 = h8,
            H9 = h9,
        };
    }

    internal readonly void ToBytes(Span<byte> s)
    {
        long h0 = H0, h1 = H1, h2 = H2, h3 = H3, h4 = H4;
        long h5 = H5, h6 = H6, h7 = H7, h8 = H8, h9 = H9;
        long q = (19 * h9 + (1L << 24)) >> 25;
        q = (h0 + q) >> 26; q = (h1 + q) >> 25; q = (h2 + q) >> 26;
        q = (h3 + q) >> 25; q = (h4 + q) >> 26; q = (h5 + q) >> 25;
        q = (h6 + q) >> 26; q = (h7 + q) >> 25; q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        h0 += 19 * q;
        long c0 = h0 >> 26; h1 += c0; h0 -= c0 << 26;
        long c1 = h1 >> 25; h2 += c1; h1 -= c1 << 25;
        long c2 = h2 >> 26; h3 += c2; h2 -= c2 << 26;
        long c3 = h3 >> 25; h4 += c3; h3 -= c3 << 25;
        long c4 = h4 >> 26; h5 += c4; h4 -= c4 << 26;
        long c5 = h5 >> 25; h6 += c5; h5 -= c5 << 25;
        long c6 = h6 >> 26; h7 += c6; h6 -= c6 << 26;
        long c7 = h7 >> 25; h8 += c7; h7 -= c7 << 25;
        long c8 = h8 >> 26; h9 += c8; h8 -= c8 << 26;
        long c9 = h9 >> 25; h9 -= c9 << 25;

        s[0] = (byte)h0;
        s[1] = (byte)(h0 >> 8);
        s[2] = (byte)(h0 >> 16);
        s[3] = (byte)((h0 >> 24) | (h1 << 2));
        s[4] = (byte)(h1 >> 6);
        s[5] = (byte)(h1 >> 14);
        s[6] = (byte)((h1 >> 22) | (h2 << 3));
        s[7] = (byte)(h2 >> 5);
        s[8] = (byte)(h2 >> 13);
        s[9] = (byte)((h2 >> 21) | (h3 << 5));
        s[10] = (byte)(h3 >> 3);
        s[11] = (byte)(h3 >> 11);
        s[12] = (byte)((h3 >> 19) | (h4 << 6));
        s[13] = (byte)(h4 >> 2);
        s[14] = (byte)(h4 >> 10);
        s[15] = (byte)(h4 >> 18);
        s[16] = (byte)h5;
        s[17] = (byte)(h5 >> 8);
        s[18] = (byte)(h5 >> 16);
        s[19] = (byte)((h5 >> 24) | (h6 << 1));
        s[20] = (byte)(h6 >> 7);
        s[21] = (byte)(h6 >> 15);
        s[22] = (byte)((h6 >> 23) | (h7 << 3));
        s[23] = (byte)(h7 >> 5);
        s[24] = (byte)(h7 >> 13);
        s[25] = (byte)((h7 >> 21) | (h8 << 4));
        s[26] = (byte)(h8 >> 4);
        s[27] = (byte)(h8 >> 12);
        s[28] = (byte)((h8 >> 20) | (h9 << 6));
        s[29] = (byte)(h9 >> 2);
        s[30] = (byte)(h9 >> 10);
        s[31] = (byte)(h9 >> 18);
    }

    internal static FieldElement Add(in FieldElement f, in FieldElement g) =>
        new FieldElement
        {
            H0 = f.H0 + g.H0,
            H1 = f.H1 + g.H1,
            H2 = f.H2 + g.H2,
            H3 = f.H3 + g.H3,
            H4 = f.H4 + g.H4,
            H5 = f.H5 + g.H5,
            H6 = f.H6 + g.H6,
            H7 = f.H7 + g.H7,
            H8 = f.H8 + g.H8,
            H9 = f.H9 + g.H9,
        };

    internal static FieldElement Sub(in FieldElement f, in FieldElement g) =>
        new FieldElement
        {
            H0 = f.H0 - g.H0,
            H1 = f.H1 - g.H1,
            H2 = f.H2 - g.H2,
            H3 = f.H3 - g.H3,
            H4 = f.H4 - g.H4,
            H5 = f.H5 - g.H5,
            H6 = f.H6 - g.H6,
            H7 = f.H7 - g.H7,
            H8 = f.H8 - g.H8,
            H9 = f.H9 - g.H9,
        };

    internal static FieldElement Negate(in FieldElement f) =>
        new FieldElement
        {
            H0 = -f.H0,
            H1 = -f.H1,
            H2 = -f.H2,
            H3 = -f.H3,
            H4 = -f.H4,
            H5 = -f.H5,
            H6 = -f.H6,
            H7 = -f.H7,
            H8 = -f.H8,
            H9 = -f.H9,
        };

    internal static FieldElement Mul(in FieldElement f, in FieldElement g)
    {
        long f0 = f.H0, f1 = f.H1, f2 = f.H2, f3 = f.H3, f4 = f.H4;
        long f5 = f.H5, f6 = f.H6, f7 = f.H7, f8 = f.H8, f9 = f.H9;
        long g0 = g.H0, g1 = g.H1, g2 = g.H2, g3 = g.H3, g4 = g.H4;
        long g5 = g.H5, g6 = g.H6, g7 = g.H7, g8 = g.H8, g9 = g.H9;

        long g1X19 = 19 * g1, g2X19 = 19 * g2, g3X19 = 19 * g3, g4X19 = 19 * g4;
        long g5X19 = 19 * g5, g6X19 = 19 * g6, g7X19 = 19 * g7, g8X19 = 19 * g8, g9X19 = 19 * g9;
        long f1X2 = 2 * f1, f3X2 = 2 * f3, f5X2 = 2 * f5, f7X2 = 2 * f7, f9X2 = 2 * f9;

        long h0 = (f0 * g0) + (f1X2 * g9X19) + (f2 * g8X19) + (f3X2 * g7X19) + (f4 * g6X19) + (f5X2 * g5X19) + (f6 * g4X19) + (f7X2 * g3X19) + (f8 * g2X19) + (f9X2 * g1X19);
        long h1 = (f0 * g1) + (f1 * g0) + (f2 * g9X19) + (f3 * g8X19) + (f4 * g7X19) + (f5 * g6X19) + (f6 * g5X19) + (f7 * g4X19) + (f8 * g3X19) + (f9 * g2X19);
        long h2 = (f0 * g2) + (f1X2 * g1) + (f2 * g0) + (f3X2 * g9X19) + (f4 * g8X19) + (f5X2 * g7X19) + (f6 * g6X19) + (f7X2 * g5X19) + (f8 * g4X19) + (f9X2 * g3X19);
        long h3 = (f0 * g3) + (f1 * g2) + (f2 * g1) + (f3 * g0) + (f4 * g9X19) + (f5 * g8X19) + (f6 * g7X19) + (f7 * g6X19) + (f8 * g5X19) + (f9 * g4X19);
        long h4 = (f0 * g4) + (f1X2 * g3) + (f2 * g2) + (f3X2 * g1) + (f4 * g0) + (f5X2 * g9X19) + (f6 * g8X19) + (f7X2 * g7X19) + (f8 * g6X19) + (f9X2 * g5X19);
        long h5 = (f0 * g5) + (f1 * g4) + (f2 * g3) + (f3 * g2) + (f4 * g1) + (f5 * g0) + (f6 * g9X19) + (f7 * g8X19) + (f8 * g7X19) + (f9 * g6X19);
        long h6 = (f0 * g6) + (f1X2 * g5) + (f2 * g4) + (f3X2 * g3) + (f4 * g2) + (f5X2 * g1) + (f6 * g0) + (f7X2 * g9X19) + (f8 * g8X19) + (f9X2 * g7X19);
        long h7 = (f0 * g7) + (f1 * g6) + (f2 * g5) + (f3 * g4) + (f4 * g3) + (f5 * g2) + (f6 * g1) + (f7 * g0) + (f8 * g9X19) + (f9 * g8X19);
        long h8 = (f0 * g8) + (f1X2 * g7) + (f2 * g6) + (f3X2 * g5) + (f4 * g4) + (f5X2 * g3) + (f6 * g2) + (f7X2 * g1) + (f8 * g0) + (f9X2 * g9X19);
        long h9 = (f0 * g9) + (f1 * g8) + (f2 * g7) + (f3 * g6) + (f4 * g5) + (f5 * g4) + (f6 * g3) + (f7 * g2) + (f8 * g1) + (f9 * g0);

        Carry(ref h0, ref h1, ref h2, ref h3, ref h4,
              ref h5, ref h6, ref h7, ref h8, ref h9);

        return new FieldElement
        {
            H0 = h0,
            H1 = h1,
            H2 = h2,
            H3 = h3,
            H4 = h4,
            H5 = h5,
            H6 = h6,
            H7 = h7,
            H8 = h8,
            H9 = h9,
        };
    }

    internal static FieldElement Square(in FieldElement f)
    {
        long f0 = f.H0, f1 = f.H1, f2 = f.H2, f3 = f.H3, f4 = f.H4;
        long f5 = f.H5, f6 = f.H6, f7 = f.H7, f8 = f.H8, f9 = f.H9;

        long f0X2 = 2 * f0, f1X2 = 2 * f1, f2X2 = 2 * f2, f3X2 = 2 * f3;
        long f4X2 = 2 * f4, f5X2 = 2 * f5, f6X2 = 2 * f6, f7X2 = 2 * f7;
        long f5X38 = 38 * f5, f6X19 = 19 * f6, f7X38 = 38 * f7;
        long f8X19 = 19 * f8, f9X38 = 38 * f9;

        long h0 = (f0 * f0) + (f1X2 * f9X38) + (f2X2 * f8X19) + (f3X2 * f7X38) + (f4X2 * f6X19) + (f5 * f5X38);
        long h1 = (f0X2 * f1) + (f2 * f9X38) + (f3X2 * f8X19) + (f4 * f7X38) + (f5X2 * f6X19);
        long h2 = (f0X2 * f2) + (f1X2 * f1) + (f3X2 * f9X38) + (f4X2 * f8X19) + (f5X2 * f7X38) + (f6 * f6X19);
        long h3 = (f0X2 * f3) + (f1X2 * f2) + (f4 * f9X38) + (f5X2 * f8X19) + (f6 * f7X38);
        long h4 = (f0X2 * f4) + (f1X2 * f3X2) + (f2 * f2) + (f5X2 * f9X38) + (f6X2 * f8X19) + (f7 * f7X38);
        long h5 = (f0X2 * f5) + (f1X2 * f4) + (f2X2 * f3) + (f6 * f9X38) + (f7X2 * f8X19);
        long h6 = (f0X2 * f6) + (f1X2 * f5X2) + (f2X2 * f4) + (f3X2 * f3) + (f7X2 * f9X38) + (f8 * f8X19);
        long h7 = (f0X2 * f7) + (f1X2 * f6) + (f2X2 * f5) + (f3X2 * f4) + (f8 * f9X38);
        long h8 = (f0X2 * f8) + (f1X2 * f7X2) + (f2X2 * f6) + (f3X2 * f5X2) + (f4 * f4) + (f9 * f9X38);
        long h9 = (f0X2 * f9) + (f1X2 * f8) + (f2X2 * f7) + (f3X2 * f6) + (f4X2 * f5);

        Carry(ref h0, ref h1, ref h2, ref h3, ref h4,
              ref h5, ref h6, ref h7, ref h8, ref h9);

        return new FieldElement
        {
            H0 = h0,
            H1 = h1,
            H2 = h2,
            H3 = h3,
            H4 = h4,
            H5 = h5,
            H6 = h6,
            H7 = h7,
            H8 = h8,
            H9 = h9,
        };
    }

    /// <summary>Inversion: z^(p-2) mod p, where p = 2^255-19.</summary>
    /// Chain from Chaos.NaCl / SUPERCOP ref10 (computes z^(2^255-21)):
    /// t0 = z^11 (saved), final result = t1^(2^5) * t0 = z^(2^255-32)*z^11 = z^(p-2).
    internal static FieldElement Invert(in FieldElement z)
    {
        var t0 = Square(z);                  // z^2
        var t1 = Square(t0); t1 = Square(t1); // z^4, z^8
        t1 = Mul(z, t1);                     // z^9
        t0 = Mul(t0, t1);                    // z^11  <-- save t0 = z^11
        var t2 = Square(t0);                 // z^22
        t1 = Mul(t1, t2);                    // z^31 = z^(2^5-1)
        t2 = Square(t1);
        for (var i = 1; i < 5; i++) t2 = Square(t2); // t2 = z^(31*2^5) = z^992
        t1 = Mul(t2, t1);                    // z^1023 = z^(2^10-1)
        t2 = Square(t1);
        for (var i = 1; i < 10; i++) t2 = Square(t2); // t2 = z^(2^20-2^10)
        t2 = Mul(t2, t1);                    // z^(2^20-1)
        var t3 = Square(t2);
        for (var i = 1; i < 20; i++) t3 = Square(t3); // t3 = z^(2^40-2^20)
        t2 = Mul(t3, t2);                    // z^(2^40-1)
        t2 = Square(t2);
        for (var i = 1; i < 10; i++) t2 = Square(t2); // t2 = z^(2^50-2^10)
        t1 = Mul(t2, t1);                    // z^(2^50-1)
        t2 = Square(t1);
        for (var i = 1; i < 50; i++) t2 = Square(t2); // t2 = z^(2^100-2^50)
        t2 = Mul(t2, t1);                    // z^(2^100-1)
        t3 = Square(t2);
        for (var i = 1; i < 100; i++) t3 = Square(t3); // t3 = z^(2^200-2^100)
        t2 = Mul(t3, t2);                    // z^(2^200-1)
        t2 = Square(t2);
        for (var i = 1; i < 50; i++) t2 = Square(t2); // t2 = z^(2^250-2^50)
        t1 = Mul(t2, t1);                    // z^(2^250-1)
        t1 = Square(t1);
        for (var i = 1; i < 5; i++) t1 = Square(t1);  // t1 = z^(2^255-32)
        return Mul(t1, t0);                  // z^(2^255-32)*z^11 = z^(2^255-21) = z^(p-2)
    }

    /// <summary>Compute z^((p-5)/8) for use in square root computation.</summary>
    internal static FieldElement Pow22523(in FieldElement z)
    {
        var t0 = Square(z);
        var t1 = Square(t0);
        t1 = Square(t1);
        t1 = Mul(z, t1);
        t0 = Mul(t0, t1);
        t0 = Square(t0);
        t0 = Mul(t1, t0);
        t1 = Square(t0);
        for (var i = 1; i < 5; i++) t1 = Square(t1);
        t0 = Mul(t1, t0);
        t1 = Square(t0);
        for (var i = 1; i < 10; i++) t1 = Square(t1);
        t1 = Mul(t1, t0);
        var t2 = Square(t1);
        for (var i = 1; i < 20; i++) t2 = Square(t2);
        t1 = Mul(t2, t1);
        t1 = Square(t1);
        for (var i = 1; i < 10; i++) t1 = Square(t1);
        t0 = Mul(t1, t0);
        t1 = Square(t0);
        for (var i = 1; i < 50; i++) t1 = Square(t1);
        t1 = Mul(t1, t0);
        t2 = Square(t1);
        for (var i = 1; i < 100; i++) t2 = Square(t2);
        t1 = Mul(t2, t1);
        t1 = Square(t1);
        for (var i = 1; i < 50; i++) t1 = Square(t1);
        t0 = Mul(t1, t0);
        t0 = Square(t0);
        t0 = Square(t0);
        return Mul(t0, z);
    }

    /// <summary>Returns true if this element is negative (i.e., its low bit when serialised is 1).</summary>
    internal readonly bool IsNegative()
    {
        Span<byte> tmp = stackalloc byte[32];
        ToBytes(tmp);
        return (tmp[0] & 1) != 0;
    }

    private static void Carry(
        ref long h0, ref long h1, ref long h2, ref long h3, ref long h4,
        ref long h5, ref long h6, ref long h7, ref long h8, ref long h9)
    {
        long c0 = (h0 + (1L << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
        long c4 = (h4 + (1L << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        long c1 = (h1 + (1L << 24)) >> 25; h2 += c1; h1 -= c1 << 25;
        long c5 = (h5 + (1L << 24)) >> 25; h6 += c5; h5 -= c5 << 25;
        long c2 = (h2 + (1L << 25)) >> 26; h3 += c2; h2 -= c2 << 26;
        long c6 = (h6 + (1L << 25)) >> 26; h7 += c6; h6 -= c6 << 26;
        long c3 = (h3 + (1L << 24)) >> 25; h4 += c3; h3 -= c3 << 25;
        long c7 = (h7 + (1L << 24)) >> 25; h8 += c7; h7 -= c7 << 25;
        c4 = (h4 + (1L << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        long c8 = (h8 + (1L << 25)) >> 26; h9 += c8; h8 -= c8 << 26;
        long c9 = (h9 + (1L << 24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
        c0 = (h0 + (1L << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
    }

    private static long Load3(ReadOnlySpan<byte> s, int offset) =>
        s[offset] | ((long)s[offset + 1] << 8) | ((long)s[offset + 2] << 16);

    private static long Load4(ReadOnlySpan<byte> s, int offset) =>
        s[offset] | ((long)s[offset + 1] << 8) | ((long)s[offset + 2] << 16) | ((long)s[offset + 3] << 24);
}
