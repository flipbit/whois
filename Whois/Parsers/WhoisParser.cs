using Tokens;
using Whois.Models;

namespace Whois.Parsers
{
    /// <summary>
    /// Parser to turn WHOIS server responses into <see cref="ParsedWhoisResponse"/>
    /// objects.
    /// </summary>
    public class WhoisParser
    {
        private readonly TokenMatcher matcher;
        private readonly ResourceReader reader;

        /// <summary>
        /// Creates a new instance of the <see cref="WhoisParser"/> class.
        /// </summary>
        public WhoisParser()
        {
            matcher = new TokenMatcher();
            reader = new ResourceReader();
        }

        /// <summary>
        /// Contains the registered templates
        /// </summary>
        public TemplateCollection Templates => matcher.Templates;

        /// <summary>
        /// Parses the WHOIS server response for the given server and TLD.
        /// </summary>
        public ParsedWhoisResponse Parse(string whoisServer, string tld, string content)
        {
            LoadServerTemplates(whoisServer, tld);

            var result = matcher.Match<ParsedWhoisResponse>(content, new []{ whoisServer, tld });

            return result.BestMatch?.Value;
        }

        private void LoadServerTemplates(string whoisServer, string tld)
        {
            // Check templates for this server/tld not already loaded
            if (Templates.ContainsAllTags(whoisServer, tld)) return;

            var templateNames = reader.GetNames(whoisServer, tld);

            foreach (var templateName in templateNames)
            {
                var content = reader.GetContent(templateName);

                matcher.RegisterTemplate(content);
            }
        }
    }
}
