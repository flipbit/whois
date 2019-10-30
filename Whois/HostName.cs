using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Tokens.Extensions;

namespace Whois
{
    public class HostName
    {
        private static readonly Regex HostNameRegex = new Regex(@"^(?!-)(xn--)?[a-zA-Z0-9][a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]{0,1}\.(?!-)(xn--)?([a-zA-Z0-9\-]{1,50}|[a-zA-Z0-9-]{1,30}\.[a-zA-Z]{2,})$");
        private static readonly Regex TldRegex = new Regex(@"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)$");

        private readonly string hostName;

        public HostName(string hostName)
        {
            if (string.IsNullOrEmpty(hostName)) throw new ArgumentNullException("hostName", "Must specify as host name.");

            // If unicode, convert to punycode
            if (HasNonAsciiChars(hostName))
            {
                hostName = ToPunyCode(hostName);
            }

            if (Uri.CheckHostName(hostName) != UriHostNameType.Dns)
            {
                throw new FormatException($"'{hostName}' is not a valid host name.");
            }

            this.hostName = hostName.ToLowerInvariant();
        }

        public bool IsPunyCode
        {
            get { return hostName.Contains("xn--"); }
        }

        public bool IsTld
        {
            get { return hostName.Contains(".") == false; }
        }

        public string Tld
        {
            get { return hostName.SubstringAfterLastString("."); }
        }

        public override string ToString()
        {
            return hostName;
        }

        public string ToUnicodeString()
        {
            return FromPunyCode(hostName);
        }

        public static HostName Parse(string value)
        {
            return new HostName(value);
        }

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

        private bool IsValidHostName(string hostName)
        {
            var valid = false;

            if (!string.IsNullOrEmpty(hostName))
            {
                valid = HostNameRegex.Match(hostName).Success;
            }

            return valid;
        }

        private bool IsValidTld(string hostName)
        {
            var valid = false;

            if (!string.IsNullOrEmpty(hostName))
            {
                valid = TldRegex.Match(hostName).Success;
            }

            return valid;
        }

        private string FromPunyCode(string hostName)
        {
            var idn = new IdnMapping();

            return idn.GetUnicode(hostName);
        }

        private string ToPunyCode(string hostName)
        {
            var idn = new IdnMapping();

            return idn.GetAscii(hostName);
        }

        private bool HasNonAsciiChars(string input)
        {
            if (string.IsNullOrEmpty(input)) return false;

            return Encoding.UTF8.GetByteCount(input) != input.Length;
        }
    }
}
