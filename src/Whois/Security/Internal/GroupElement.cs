using System.Runtime.InteropServices;

namespace Whois.Security.Internal;

/// <summary>
/// A point on the Ed25519 curve in extended twisted Edwards coordinates (X:Y:Z:T)
/// where x = X/Z, y = Y/Z, x*y = T/Z.
/// Based on the SUPERCOP ref10 representation.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct GroupElement
{
    internal FieldElement X;
    internal FieldElement Y;
    internal FieldElement Z;
    internal FieldElement T;

    /// <summary>The neutral (identity) element: (0:1:1:0).</summary>
    internal static readonly GroupElement Identity = new GroupElement
    {
        X = FieldElement.Zero,
        Y = FieldElement.One,
        Z = FieldElement.One,
        T = FieldElement.Zero,
    };

    /// <summary>The Ed25519 base point B.</summary>
    internal static readonly GroupElement BasePoint = new GroupElement
    {
        // X component (compressed, little-endian)
        X = FieldElement.FromBytes(new byte[]
        {
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
            0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
            0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
            0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
        }),
        // Y component = 4/5 mod p  (the canonical y for Ed25519)
        Y = FieldElement.FromBytes(new byte[]
        {
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        }),
        Z = FieldElement.One,
        // T = X*Y
        T = FieldElement.FromBytes(new byte[]
        {
            0xa3, 0xdd, 0xb7, 0xa5, 0xb3, 0x8a, 0xde, 0x6d,
            0xf5, 0x52, 0x51, 0x77, 0x80, 0x9f, 0xf0, 0x20,
            0x7d, 0xe3, 0xab, 0x64, 0x8e, 0x4e, 0xea, 0x66,
            0x65, 0x76, 0x8b, 0xd7, 0x0f, 0x5f, 0x87, 0x67,
        }),
    };

    /// <summary>
    /// Decodes a compressed point from 32 bytes.
    /// Returns false if the input does not encode a valid point on the curve.
    /// </summary>
    internal static bool TryFromBytes(out GroupElement p, ReadOnlySpan<byte> s)
    {
        p = default;
        if (s.Length != 32) return false;

        Span<byte> tmp = stackalloc byte[32];
        s.CopyTo(tmp);
        var xSign = tmp[31] >> 7;
        tmp[31] &= 0x7f;

        var y = FieldElement.FromBytes(tmp);
        var y2 = FieldElement.Square(y);

        // u = y^2 - 1;  v = d*y^2 + 1
        var u = FieldElement.Sub(y2, FieldElement.One);
        var v = FieldElement.Add(FieldElement.Mul(FieldElement.D, y2), FieldElement.One);

        // x candidate = u * v^3 * (u * v^7)^((p-5)/8)
        var v3 = FieldElement.Mul(FieldElement.Square(v), v);
        var v7 = FieldElement.Mul(FieldElement.Square(v3), v);
        var uv3 = FieldElement.Mul(u, v3);
        var uv7 = FieldElement.Mul(u, v7);
        var x = FieldElement.Mul(uv3, FieldElement.Pow22523(uv7));

        // Check v * x^2 == u; if not, try x *= sqrt(-1)
        var vxx = FieldElement.Mul(v, FieldElement.Square(x));
        Span<byte> checkBytes = stackalloc byte[32];
        FieldElement.Sub(vxx, u).ToBytes(checkBytes);

        if (!IsZero(checkBytes))
        {
            x = FieldElement.Mul(x, FieldElement.SqrtM1);
            vxx = FieldElement.Mul(v, FieldElement.Square(x));
            FieldElement.Sub(vxx, u).ToBytes(checkBytes);
            if (!IsZero(checkBytes)) return false;
        }

        if (x.IsNegative() != (xSign == 1))
        {
            x = FieldElement.Negate(x);
        }

        p = new GroupElement
        {
            X = x,
            Y = y,
            Z = FieldElement.One,
            T = FieldElement.Mul(x, y),
        };
        return true;
    }

    /// <summary>Serialises the point to compressed 32-byte form.</summary>
    internal readonly void ToBytes(Span<byte> s)
    {
        var recip = FieldElement.Invert(Z);
        var x = FieldElement.Mul(X, recip);
        var y = FieldElement.Mul(Y, recip);
        y.ToBytes(s);
        Span<byte> xBytes = stackalloc byte[32];
        x.ToBytes(xBytes);
        s[31] |= (byte)((xBytes[0] & 1) << 7);
    }

    /// <summary>Negates the point in place (flip sign of X and T).</summary>
    internal static void NegateSelf(ref GroupElement p)
    {
        p.X = FieldElement.Negate(p.X);
        p.T = FieldElement.Negate(p.T);
    }

    /// <summary>
    /// Variable-time double-scalar multiplication: computes [a]B + [b]A.
    /// Only safe to call for signature verification, never for signing.
    /// </summary>
    internal static GroupElement DoubleScalarMulVartime(
        ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ref GroupElement externalA)
    {
        var result = Identity;
        var localB = BasePoint;

        for (var i = 255; i >= 0; i--)
        {
            result = PointDouble(in result);

            var bitA = (a[i >> 3] >> (i & 7)) & 1;
            var bitB = (b[i >> 3] >> (i & 7)) & 1;

            if (bitA == 1 && bitB == 1)
            {
                var tmp = PointAdd(in result, in localB);
                result = PointAdd(in tmp, in externalA);
            }
            else if (bitA == 1)
            {
                result = PointAdd(in result, in localB);
            }
            else if (bitB == 1)
            {
                result = PointAdd(in result, in externalA);
            }
        }

        return result;
    }

    /// <summary>
    /// Checks whether two points are equal mod the cofactor (i.e., 8*p == 8*q).
    /// </summary>
    internal static bool EqualsCofactor(in GroupElement p, in GroupElement q)
    {
        var p2 = PointDouble(in p);
        var p4 = PointDouble(in p2);
        var p8 = PointDouble(in p4);
        var q2 = PointDouble(in q);
        var q4 = PointDouble(in q2);
        var q8 = PointDouble(in q4);

        Span<byte> pBytes = stackalloc byte[32];
        Span<byte> qBytes = stackalloc byte[32];
        p8.ToBytes(pBytes);
        q8.ToBytes(qBytes);

        return pBytes.SequenceEqual(qBytes);
    }

    private static GroupElement PointAdd(in GroupElement p, in GroupElement q)
    {
        var a = FieldElement.Mul(FieldElement.Sub(p.Y, p.X), FieldElement.Sub(q.Y, q.X));
        var b = FieldElement.Mul(FieldElement.Add(p.Y, p.X), FieldElement.Add(q.Y, q.X));
        var c = FieldElement.Mul(FieldElement.Mul(p.T, FieldElement.D2), q.T);
        var d = FieldElement.Mul(FieldElement.Add(p.Z, p.Z), q.Z);
        var e = FieldElement.Sub(b, a);
        var f = FieldElement.Sub(d, c);
        var g = FieldElement.Add(d, c);
        var h = FieldElement.Add(b, a);

        return new GroupElement
        {
            X = FieldElement.Mul(e, f),
            Y = FieldElement.Mul(g, h),
            Z = FieldElement.Mul(f, g),
            T = FieldElement.Mul(e, h),
        };
    }

    private static GroupElement PointDouble(in GroupElement p)
    {
        var a = FieldElement.Square(p.X);
        var b = FieldElement.Square(p.Y);
        var c = FieldElement.Add(FieldElement.Square(p.Z), FieldElement.Square(p.Z));
        var h = FieldElement.Add(a, b);
        var xy = FieldElement.Add(p.X, p.Y);
        var e = FieldElement.Sub(h, FieldElement.Square(xy));
        var g = FieldElement.Sub(a, b);
        var f = FieldElement.Add(c, g);

        return new GroupElement
        {
            X = FieldElement.Mul(e, f),
            Y = FieldElement.Mul(g, h),
            Z = FieldElement.Mul(f, g),
            T = FieldElement.Mul(e, h),
        };
    }

    private static bool IsZero(ReadOnlySpan<byte> s)
    {
        foreach (var b in s)
        {
            if (b != 0) return false;
        }

        return true;
    }
}
