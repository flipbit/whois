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

            Embedded.Patterns.Domains.ForEach((name, pattern) =>
            {
                matcher.AddPattern(pattern, name);
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
                if (matcher.TryMatch<ParsedWhoisResponse>(state.Response.Content, out var match))
                {
                    Log.Debug("Parsed WHOIS data using pattern {0} - {1} replacement(s) made.", match.Template.Name, match.Matches);

                    state.Response.ParsedResponse = match.Result;
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

        public void AddPattern(string content, string name)
        {
            matcher.AddPattern(content, name);
        }

        public void ClearPatterns()
        {
            matcher.ClearPatterns();
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