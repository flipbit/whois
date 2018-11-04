using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Whois.Visitors
{
    public class ValidateVisitor : IWhoisVisitor
    {
        public Task<LookupState> Visit(LookupState state)
        {
            if (string.IsNullOrEmpty(state.Domain))
            {
                throw new WhoisException($"Domain Name not specified.");
            }

            state.Domain = state.Domain.Trim();

            if (IsValidDomainName(state.Domain) == false)
            {
                throw new WhoisException($"Domain Name is invalid: {state.Domain}");
            }

            state.Tld = GetTld(state.Domain);

            return Task.FromResult(state);
        }

        private string GetTld(string domain)
        {
            var tld = domain;

            if (!string.IsNullOrEmpty(domain))
            {
                var parts = domain.Split('.');

                if (parts.Length > 1) tld = parts[parts.Length - 1];
            }

            return tld;
        }

        public bool IsValidDomainName(string domain)
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
