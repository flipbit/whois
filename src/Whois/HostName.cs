using System;
using System.Globalization;
using System.Text;
using Tokens.Extensions;

namespace Whois
{
    /// <summary>
    /// Represents an Internet host name.
    /// </summary>
    public class HostName
    {
        /// <summary>
        /// Create a new <see cref="HostName"/> with the given string.
        /// </summary>
        public HostName(string hostName)
        {
            if (string.IsNullOrEmpty(hostName))
            {
                throw new ArgumentNullException("hostName", "Must specify as host name.");
            }

            // If input is unicode, convert to punycode
            if (HasNonAsciiChars(hostName))
            {
                hostName = ToPunyCode(hostName);
            }

            // Check valid
            if (Uri.CheckHostName(hostName) != UriHostNameType.Dns)
            {
                throw new FormatException($"'{hostName}' is not a valid host name.");
            }

            Value = hostName.ToLowerInvariant();
        }

        /// <summary>
        /// Determines if the host name is PunyCode encoded
        /// </summary>
        public bool IsPunyCode => Value.Contains("xn--");

        /// <summary>
        /// Determines if the host name is an internet Top Level Domain (TLD)
        /// </summary>
        public bool IsTld => Value.Contains(".") == false;

        /// <summary>
        /// Gets the TLD part of the hostname, e.g. "com" for "example.com"
        /// </summary>
        public string Tld => Value.SubstringAfterLastString(".");

        /// <summary>
        /// Gets the string value of the host name.
        /// </summary>
        public string Value { get; }

        /// <summary>
        /// Returns a string representing the host name.
        /// </summary>
        public override string ToString()
        {
            return Value;
        }

        /// <summary>
        /// Returns a Unicode encoded version of the host name.
        /// </summary>
        public string ToUnicodeString()
        {
            return FromPunyCode(Value);
        }

        public bool IsEqualTo(HostName other)
        {
            if (other == null) return false;

            return string.Compare(Value, other.Value, StringComparison.InvariantCultureIgnoreCase) == 0;
        }

        /// <summary>
        /// Parses the given value and returns a <see cref="HostName"/>.
        /// </summary>
        public static HostName Parse(string value)
        {
            return new HostName(value);
        }

        /// <summary>
        /// Attempts to parse the given value into a <see cref="HostName"/>.  Returns
        /// true if successful.
        /// </summary>
        public static bool TryParse(string value, out HostName hostName)
        {
            try
            {
                hostName = new HostName(value);

                return true;
            }
            catch (ArgumentNullException)
            {
                hostName = null;

                return false;
            }
            catch (FormatException)
            {
                hostName = null;

                return false;
            }
        }

        private static string FromPunyCode(string hostName)
        {
            var idn = new IdnMapping();

            return idn.GetUnicode(hostName);
        }

        private static string ToPunyCode(string hostName)
        {
            var idn = new IdnMapping();

            return idn.GetAscii(hostName);
        }

        private static bool HasNonAsciiChars(string input)
        {
            if (string.IsNullOrEmpty(input)) return false;

            return Encoding.UTF8.GetByteCount(input) != input.Length;
        }
    }
}
