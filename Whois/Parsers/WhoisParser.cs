using System.Collections.Generic;
using System.Linq;
using Tokens;
using Tokens.Transformers;
using Tokens.Validators;
using Whois.Models;
using Whois.Parsers.Fixups;

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
        private readonly WhoisResponseStatusParser statusParser;

        /// <summary>
        /// Creates a new instance of the <see cref="WhoisParser"/> class.
        /// </summary>
        public WhoisParser()
        {
            matcher = new TokenMatcher();
            reader = new ResourceReader();
            statusParser = new WhoisResponseStatusParser();
            FixUps = new List<IFixup>();

            // Register default transformers
            matcher.RegisterTransformer<CleanDomainStatusTransformer>();

            // Register default FixUps
            FixUps.Add(new MultipleContactFixup());
        }

        /// <summary>
        /// Contains the registered templates
        /// </summary>
        public TemplateCollection Templates => matcher.Templates;

        /// <summary>
        /// Template Fixups
        /// </summary>
        public IList<IFixup> FixUps { get; }

        /// <summary>
        /// Parses the WHOIS server response for the given server and TLD.
        /// </summary>
        public WhoisResponse Parse(string whoisServer, string tld, string content)
        {
            LoadServerTemplates(whoisServer, tld);
            LoadServerTemplates(whoisServer);

            var result = matcher.Match<WhoisResponse>(content, new []{ whoisServer, tld });

            var match = result.BestMatch;

            if (match == null)
            {
                LoadServerGenericTemplates();

                match = matcher
                    .Match<WhoisResponse>(content, new [] { "catch-all" })
                    .BestMatch;
            }

            if (match != null)
            {
                // Perform extended processing on parsed data
                // via FixUps.
                foreach (var fixup in FixUps)
                {
                    if (fixup.CanFixup(match))
                    {
                        fixup.Fixup(match);
                    }
                }

                var value = match.Value;

                value.FieldsParsed = match.Tokens.Matches.Count;
                value.ParsingErrors = match.Exceptions.Count;
                value.TemplateName = match.Template.Name;

                var status = statusParser.Parse(whoisServer, tld, value.DomainStatus.FirstOrDefault(), value.Status);

                value.Status = status;

                return value;
            }

            return null;
        }

        public void AddTemplate(string content, string name)
        {
            matcher.RegisterTemplate(content, name);
        }

        public void ClearTemplates()
        {
            matcher.Templates.Clear();
        }

        public void RegisterValidator<T>() where T : ITokenValidator
        {
            matcher.RegisterValidator<T>();
        }

        public void RegisterTransformer<T>() where T : ITokenTransformer
        {
            matcher.RegisterTransformer<T>();
        }

        private void LoadServerTemplates(string whoisServer, string tld)
        {
            // Check templates for this server/tld not already loaded
            var loaded = Templates
                .Where(t => t.Name.Contains("generic") == false)
                .Any(t => t.HasTags(new [] {whoisServer, tld}));

            if (loaded) return;

            var templateNames = reader.GetNames(whoisServer, tld);

            foreach (var templateName in templateNames)
            {
                var content = reader.GetContent(templateName);

                matcher.RegisterTemplate(content);
            }
        }

        private void LoadServerTemplates(string whoisServer)
        {
            // Check templates for this server/tld not already loaded
            var loaded = Templates
                .Where(t => t.Name.Contains("generic") == false)
                .Any(t => t.HasTags(new [] {whoisServer}));

            if (loaded) return;

            var templateNames = reader.GetNames(whoisServer);

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
