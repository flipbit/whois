using System.Collections.Generic;
using System.Linq;
using Tokens;
using Tokens.Exceptions;
using Tokens.Transformers;
using Whois.Parsers.Fixups;

namespace Whois.Parsers
{
    /// <summary>
    /// Parser to turn WHOIS server responses into <see cref="WhoisResponse"/>
    /// objects.
    /// </summary>
    public class WhoisParser
    {
        private const string GenericTemplateTag = "catch-all";

        private readonly TemplateMatcher matcher;
        private readonly ResourceReader reader;
        private readonly WhoisStatusParser statusParser;

        /// <summary>
        /// Creates a new instance of the <see cref="WhoisParser"/> class.
        /// </summary>
        public WhoisParser()
        {
            var options = new TokenizerOptions()
                .WithTransformer<CleanDomainStatusTransformer>()
                .WithTransformer<ToHostNameTransformer>();

            matcher = new TemplateMatcher(options);
            reader = new ResourceReader();
            statusParser = new WhoisStatusParser();
            FixUps = new List<IFixup>();

            // Register default FixUps
            FixUps.Add(new MultipleContactFixup());
            FixUps.Add(new WhoisIsocOrgIlFixup());
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
        public WhoisResponse Parse(string whoisServer, string content)
        {
            if (string.IsNullOrEmpty(content))
            {
                return new WhoisResponse
                {
                    Content = content,
                    Status = WhoisStatus.Unknown
                };
            }

            LoadServerTemplates(whoisServer);

            var result = matcher.Tokenize(content, new []{ whoisServer });

            var match = result.BestMatch;

            if (match == null)
            {
                LoadServerGenericTemplates();

                match = matcher
                    .Tokenize(content, new [] { "catch-all" })
                    .BestMatch;
            }

            if (match != null)
            {
                WhoisResponse value;
                var assignmentErrors = 0;
                try
                {
                    value = match.Assign<WhoisResponse>();
                }
                catch (AssignmentFailedException ex)
                {
                    value = (WhoisResponse)ex.PartialResult!;
                    assignmentErrors = ex.Errors.Count;
                }

                // Perform extended processing on parsed data
                // via FixUps.
                foreach (var fixup in FixUps)
                {
                    if (fixup.CanFixup(match))
                    {
                        fixup.Fixup(match, value);
                    }
                }

                value.Content = content;
                value.FieldsParsed = match.Tokens.Matches.Count;
                value.ParsingErrors = match.Exceptions.Count + assignmentErrors;
                value.TemplateName = match.Template.Name;

                var status = statusParser.Parse(whoisServer, value.DomainStatus.FirstOrDefault(), value.Status);

                value.Status = status;

                return value;
            }

            return new WhoisResponse
            {
                Content = content,
                Status = WhoisStatus.Unknown
            };
        }

        public void AddTemplate(string content, string name)
        {
            matcher.RegisterTemplate(content, name);
        }

        public void ClearTemplates()
        {
            matcher.Templates.Clear();
        }

        private void LoadServerTemplates(string whoisServer)
        {
            // Check templates for this server/tld not already loaded
            var loaded = Templates.ContainsTag(whoisServer);

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
            if (Templates.ContainsTag(GenericTemplateTag)) return;

            var templateNames = reader.GetNames("generic", "tld");

            foreach (var templateName in templateNames)
            {
                var content = reader.GetContent(templateName);

                matcher.RegisterTemplate(content);
            }
        }
    }
}
