using System.Globalization;

namespace Whois.Templates;

/// <summary>
/// Parses and compares four-part numeric version strings (e.g. "2026.07.12.1").
/// </summary>
public static class TemplateVersion
{
    /// <summary>
    /// Attempts to parse a four-part version string into its integer components.
    /// Accepts strings matching <c>^\d+\.\d+\.\d+\.\d+$</c>.
    /// </summary>
    /// <param name="version">The version string to parse.</param>
    /// <param name="components">The four parsed integer components, or <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> if parsing succeeded; otherwise <see langword="false"/>.</returns>
    public static bool TryParse(string version, out int[]? components)
    {
        components = null;

        if (string.IsNullOrEmpty(version)) return false;

        var parts = version.Split('.');
        if (parts.Length != 4) return false;

        var result = new int[4];
        for (var i = 0; i < 4; i++)
        {
            if (parts[i].Length == 0) return false;

            // Reject non-digit characters
            foreach (var ch in parts[i])
            {
                if (ch < '0' || ch > '9') return false;
            }

            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out result[i]))
                return false;
        }

        components = result;
        return true;
    }

    /// <summary>
    /// Compares two four-component version arrays left-to-right numerically.
    /// </summary>
    /// <returns>
    /// A negative integer if <paramref name="a"/> is less than <paramref name="b"/>,
    /// zero if equal, or a positive integer if <paramref name="a"/> is greater than <paramref name="b"/>.
    /// </returns>
    public static int Compare(int[] a, int[] b)
    {
        for (var i = 0; i < 4; i++)
        {
            var diff = a[i] - b[i];
            if (diff != 0) return diff;
        }

        return 0;
    }
}
