using System;
using System.Threading.Tasks;
using Tokens;
using Tokens.Transformers;
using Tokens.Validators;
using Whois.Logging;
using Whois.Models;
using Whois.Resources;

namespace Whois.Visitors
{
    /// <summary>
    /// Parses WHOIS data and extracts data into structured objects
    /// </summary>
    public class PatternExtractorVisitor : IWhoisVisitor
    {
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();

        private readonly TokenMatcher matcher;

        public PatternExtractorVisitor()
        {
            matcher = new TokenMatcher();

            // Support UTC DateTimes
            matcher.RegisterTransformer<ToDateTimeUtcTransformer>();

            Embedded.Patterns.Domains.ForEach((name, pattern) =>
            {
                matcher.RegisterTemplate(pattern, name);
            });
        }

        public Task<LookupState> Visit(LookupState state)
        {
            if (state.Options.ParseWhoisResponse == false)
            {
                return Task.FromResult(state);
            }

            try
            {
                var matchResult = Parse(state.Response.Content);
                var match = matchResult.BestMatch;

                if (match != null && match.Success)
                {
                    Log.Debug("Parsed WHOIS data using pattern {0} - {1} replacement(s) made.", match.Template.Name, match.Tokens.Matches.Count);

                    state.Response.ParsedResponse = match.Value;
                }
                else
                {
                    Log.Debug("Unable to parse WHOIS data.");
                }
            }
            catch (Exception e)
            {
                Log.Error(e, "Error parsing WHOIS DATA for: {0}", state.Domain);

                if (state.Options.ThrowOnParsingException) throw;
            }

            return Task.FromResult(state);
        }

        public TokenMatcherResult<ParsedWhoisResponse> Parse(string whoisContent)
        {
            return matcher.Match<ParsedWhoisResponse>(whoisContent);
        }

        public void AddPattern(string content, string name)
        {
            matcher.RegisterTemplate(content, name);
        }

        public void ClearPatterns()
        {
            matcher.Templates.Clear();
        }

        public void RegisterPatternValidator<T>() where T : ITokenValidator
        {
            matcher.RegisterValidator<T>();
        }

        public void RegisterPatternTransformer<T>() where T : ITokenTransformer
        {
            matcher.RegisterTransformer<T>();
        }
    }
}