using System;

namespace Whois.Extensions
{
    /// <summary>
    /// String extension class
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        /// Substrings the after char.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="match">The match.</param>
        /// <returns></returns>
        public static string SubstringAfterChar(this string value, string match)
        {
            var result = value;

            if (!string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(match))
            {
                if (value.Contains(match))
                {
                    result = value.Substring(value.IndexOf(match, StringComparison.Ordinal) + match.Length);
                }
            }

            return result;
        }

        /// <summary>
        /// Substrings the before char.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="match">The match.</param>
        /// <returns></returns>
        public static string SubstringBeforeChar(this string value, string match)
        {
            var result = value;

            if (!string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(match))
            {
                if (value.Contains(match))
                {
                    result = value.Substring(0, value.IndexOf(match, StringComparison.Ordinal));
                }
            }

            return result;
        }
    }
}