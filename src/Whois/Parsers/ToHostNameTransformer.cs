using System;
using Tokens.Transformers;

namespace Whois.Parsers
{
    /// <summary>
    /// Converts a string into a <see cref="HostName"/.
    /// </summary>
    public class ToHostNameTransformer : ITokenTransformer
    {
        public bool CanTransform(object value, string[] args, out object transformed)
        {
            if (value == null)
            {
                transformed = null;
                return true;
            }

            var valueString = value.ToString();

            if (string.IsNullOrEmpty(valueString))
            {
                transformed = null;
                return true;
            }

            if (HostName.TryParse(valueString, out var hostName))
            {
                transformed = hostName;
                return true;
            }

            transformed = null;

            return false;
        }
    }
}
