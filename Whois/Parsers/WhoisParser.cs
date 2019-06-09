using System.Collections.Generic;
using System.Linq;
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
            LoadServerGenericTemplates();

            var result = matcher.Match<ParsedWhoisResponse>(content, new []{ whoisServer, tld });

            var match = result.BestMatch;

            if (match != null)
            {
                var value = match.Value;

                value.FieldsParsed = match.Tokens.Matches.Count;
                value.ParsingErrors = match.Exceptions.Count;
                value.TemplateName = match.Template.Name;

                return value;
            }

            return null;
        }

        private void LoadServerTemplates(string whoisServer, string tld)
        {
            // Check templates for this server/tld not already loaded
            var loaded = Templates
                .Where(t => t.Name.Contains("generic") == false)
                .Any(t => t.HasAllTags(new [] {whoisServer, tld}));

            if (loaded) return;

            var templateNames = reader.GetNames(whoisServer, tld);

            foreach (var templateName in templateNames)
            {
                var content = reader.GetContent(templateName);

                matcher.RegisterTemplate(content);
            }
        }

        private void LoadServerGenericTemplates()
        {
            if (Templates.Select(t => t.Name).Any(n => n.Contains("generic"))) return;

            var templateNames = reader.GetNames("generic", "tld");

            foreach (var templateName in templateNames)
            {
                var content = reader.GetContent(templateName);

                matcher.RegisterTemplate(content);
            }
        }
    }
}
