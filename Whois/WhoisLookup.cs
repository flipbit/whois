using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Tokens.Transformers;
using Tokens.Validators;
using Whois.Logging;
using Whois.Models;
using Whois.Net;
using Whois.Parsers;
using Whois.Servers;

namespace Whois
{
    /// <summary>
    /// Looks up WHOIS information
    /// </summary>
    public class WhoisLookup : IWhoisLookup
    {
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();
        
        private WhoisParser whoisParser;

        public WhoisOptions Options { get; set; }

        public IWhoisServerLookup ServerLookup { get; set; }

        public WhoisLookup() : this(WhoisOptions.Defaults.Clone())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class.
        /// </summary>
        public WhoisLookup(WhoisOptions options) 
        {
            Options = options;
            whoisParser = new WhoisParser();
            ServerLookup = new IanaServerLookup();
        }

        public WhoisResponse Lookup(string domain)
        {
            return AsyncHelper.RunSync(() => LookupAsync(domain));
        }

        public WhoisResponse Lookup(string domain, Encoding encoding)
        {
            return AsyncHelper.RunSync(() => LookupAsync(domain, encoding));
        }

        public async Task<WhoisResponse> LookupAsync(string domain)
        {
            return await LookupAsync(domain, Options.DefaultEncoding);
        }

        public async Task<WhoisResponse> LookupAsync(string domain, Encoding encoding)
        {
            if (string.IsNullOrEmpty(domain))
            {
                throw new ArgumentNullException("domain");
            }

            if (IsValidDomainName(domain) == false)
            {
                throw new WhoisException($"Domain Name is invalid: {domain}");
            }

            Log.Debug("Looking up WHOIS response for: {0}", domain);

            var tld = GetTld(domain);

            var whoisServer = await ServerLookup.LookupAsync(tld);

            var response = new WhoisResponse();
            var whoisServerUrl = whoisServer?.Registrar?.WhoisServerUrl;

            while (string.IsNullOrEmpty(whoisServerUrl) == false)
            {
                var content = await Download(whoisServerUrl, domain, encoding);

                response = whoisParser.Parse(whoisServerUrl, tld, content);

                response.Content = content;

                if (response.Registrar?.WhoisServerUrl == whoisServerUrl) break;
            
                whoisServerUrl = response.Registrar?.WhoisServerUrl;
            }

            return response;
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

        private async Task<string> Download(string url, string domainName, Encoding encoding)
        {
            string content;

            if (domainName.EndsWith("jp")) domainName += "/e";

            using (var tcpReader = TcpReaderFactory.Create())
            {
                content = await tcpReader.Read(url, 43, domainName, encoding);
            }

            Log.Debug("Lookup {0}: Downloaded {1:###,###,##0} byte(s) from {2}.", domainName, content.Length, url);

            return content;
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
    }
}