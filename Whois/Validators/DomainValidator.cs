using System.Text.RegularExpressions;

namespace Whois.Validators
{
    /// <summary>
    /// 
    /// </summary>
    public class DomainValidator
    {
        /// <summary>
        /// Validates the specified URL.
        /// </summary>
        /// <param name="domain">The URL.</param>
        /// <returns></returns>
        public bool Valid(string domain)
        {
            var valid = false;

            if (!string.IsNullOrEmpty(domain))
            {
                var regex = new Regex(@"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$");

                valid = regex.Match(domain).Success;
            }

            return valid;
        }
    }
}
