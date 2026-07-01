using System;

namespace Whois
{
    /// <summary>
    /// Occurs when an exception is thrown during a WHOIS lookup
    /// </summary>
    public class WhoisException : Exception
    {
        public WhoisException(string message) : base(message)
        {
        }

        public WhoisException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public override string Message
        {
            get
            {
                return $"{base.Message}{Environment.NewLine}{Environment.NewLine}Please log issues at:{Environment.NewLine}https://github.com/flipbit/whois/issues";
            }
        }
    }
}
