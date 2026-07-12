namespace Whois.Security.Internal;

/// <summary>
/// Arithmetic on scalars modulo the Ed25519 group order L.
/// L = 2^252 + 27742317777372353535851937790883648493
/// </summary>
internal static class ScalarOps
{
    // L in little-endian byte form
    private static ReadOnlySpan<byte> L => new byte[]
    {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };

    /// <summary>Returns true if the 32-byte little-endian scalar is in [0, L).</summary>
    internal static bool IsCanonical(ReadOnlySpan<byte> s)
    {
        var l = L;
        for (var i = 31; i >= 0; i--)
        {
            if (s[i] < l[i]) return true;
            if (s[i] > l[i]) return false;
        }

        return false; // s == L is not canonical
    }

    /// <summary>
    /// Reduces a 64-byte scalar mod L in place.
    /// The result occupies the first 32 bytes; the upper bytes are zeroed.
    /// </summary>
    internal static void Reduce(Span<byte> s)
    {
        // Load as 21-bit limbs and reduce using the standard schoolbook method
        // from the SUPERCOP ref10 implementation / RFC 8032 appendix.
        long s0 = 2097151L & Load3(s, 0);
        long s1 = 2097151L & (Load4(s, 2) >> 5);
        long s2 = 2097151L & (Load3(s, 5) >> 2);
        long s3 = 2097151L & (Load4(s, 7) >> 7);
        long s4 = 2097151L & (Load4(s, 10) >> 4);
        long s5 = 2097151L & (Load3(s, 13) >> 1);
        long s6 = 2097151L & (Load4(s, 15) >> 6);
        long s7 = 2097151L & (Load3(s, 18) >> 3);
        long s8 = 2097151L & Load3(s, 21);
        long s9 = 2097151L & (Load4(s, 23) >> 5);
        long s10 = 2097151L & (Load3(s, 26) >> 2);
        long s11 = 2097151L & (Load4(s, 28) >> 7);
        long s12 = 2097151L & (Load4(s, 31) >> 4);
        long s13 = 2097151L & (Load3(s, 34) >> 1);
        long s14 = 2097151L & (Load4(s, 36) >> 6);
        long s15 = 2097151L & (Load3(s, 39) >> 3);
        long s16 = 2097151L & Load3(s, 42);
        long s17 = 2097151L & (Load4(s, 44) >> 5);
        long s18 = 2097151L & (Load3(s, 47) >> 2);
        long s19 = 2097151L & (Load4(s, 49) >> 7);
        long s20 = 2097151L & (Load4(s, 52) >> 4);
        long s21 = 2097151L & (Load3(s, 55) >> 1);
        long s22 = 2097151L & (Load4(s, 57) >> 6);
        long s23 = Load4(s, 60) >> 3;

        // Eliminate s23..s18 downward using the mu coefficients derived from L
        ReduceHigh(ref s11, ref s12, ref s13, ref s14, ref s15, ref s16, s23);
        ReduceHigh(ref s10, ref s11, ref s12, ref s13, ref s14, ref s15, s22);
        ReduceHigh(ref s9, ref s10, ref s11, ref s12, ref s13, ref s14, s21);
        ReduceHigh(ref s8, ref s9, ref s10, ref s11, ref s12, ref s13, s20);
        ReduceHigh(ref s7, ref s8, ref s9, ref s10, ref s11, ref s12, s19);
        ReduceHigh(ref s6, ref s7, ref s8, ref s9, ref s10, ref s11, s18);

        long carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        long carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        long carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        long carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        long carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        long carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
        long carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        long carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        long carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        long carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        long carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

        ReduceHigh(ref s5, ref s6, ref s7, ref s8, ref s9, ref s10, s17);
        ReduceHigh(ref s4, ref s5, ref s6, ref s7, ref s8, ref s9, s16);
        ReduceHigh(ref s3, ref s4, ref s5, ref s6, ref s7, ref s8, s15);
        ReduceHigh(ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, s14);
        ReduceHigh(ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, s13);
        ReduceHigh(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, s12);
        s12 = 0;

        long carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        long carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        long carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        long carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        long carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        long carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

        ReduceHigh(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, s12);
        s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

        ReduceHigh(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, s12);
        s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

        // Pack the 12 limbs back to 32 bytes
        s[0] = (byte)s0;
        s[1] = (byte)(s0 >> 8);
        s[2] = (byte)((s0 >> 16) | (s1 << 5));
        s[3] = (byte)(s1 >> 3);
        s[4] = (byte)(s1 >> 11);
        s[5] = (byte)((s1 >> 19) | (s2 << 2));
        s[6] = (byte)(s2 >> 6);
        s[7] = (byte)((s2 >> 14) | (s3 << 7));
        s[8] = (byte)(s3 >> 1);
        s[9] = (byte)(s3 >> 9);
        s[10] = (byte)((s3 >> 17) | (s4 << 4));
        s[11] = (byte)(s4 >> 4);
        s[12] = (byte)(s4 >> 12);
        s[13] = (byte)((s4 >> 20) | (s5 << 1));
        s[14] = (byte)(s5 >> 7);
        s[15] = (byte)((s5 >> 15) | (s6 << 6));
        s[16] = (byte)(s6 >> 2);
        s[17] = (byte)(s6 >> 10);
        s[18] = (byte)((s6 >> 18) | (s7 << 3));
        s[19] = (byte)(s7 >> 5);
        s[20] = (byte)(s7 >> 13);
        s[21] = (byte)s8;
        s[22] = (byte)(s8 >> 8);
        s[23] = (byte)((s8 >> 16) | (s9 << 5));
        s[24] = (byte)(s9 >> 3);
        s[25] = (byte)(s9 >> 11);
        s[26] = (byte)((s9 >> 19) | (s10 << 2));
        s[27] = (byte)(s10 >> 6);
        s[28] = (byte)((s10 >> 14) | (s11 << 7));
        s[29] = (byte)(s11 >> 1);
        s[30] = (byte)(s11 >> 9);
        s[31] = (byte)(s11 >> 17);

        for (var i = 32; i < s.Length; i++) s[i] = 0;
    }

    // Eliminates limb sN by folding it back into s0..s5 using:
    //   666643, 470296, 654183, -997805, 136657, -683901
    // These are the coefficients of (2^252) mod L decomposed into 21-bit limbs.
    private static void ReduceHigh(
        ref long s0, ref long s1, ref long s2,
        ref long s3, ref long s4, ref long s5,
        long sN)
    {
        s0 += sN * 666643;
        s1 += sN * 470296;
        s2 += sN * 654183;
        s3 -= sN * 997805;
        s4 += sN * 136657;
        s5 -= sN * 683901;
    }

    private static long Load3(ReadOnlySpan<byte> s, int offset) =>
        s[offset] | ((long)s[offset + 1] << 8) | ((long)s[offset + 2] << 16);

    private static long Load4(ReadOnlySpan<byte> s, int offset) =>
        s[offset] | ((long)s[offset + 1] << 8) | ((long)s[offset + 2] << 16) | ((long)s[offset + 3] << 24);
}
