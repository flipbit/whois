using System;
using System.Threading.Tasks;
using Tokens;
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
            if (state.ParseResponse == false)
            {
                return Task.FromResult(state);
            }

            if (matcher.TryMatch<ParsedWhoisResponse>(state.Response.Content, out var match))
            {
                Log.Debug("Parsed WHOIS data using pattern {0} - {1} replacement(s) made.", match.Template.Name, match.Matches);

                state.Response.ParsedResponse = match.Result;
            }
            else
            {
                Log.Debug("Unable to parse WHOIS data.");
            }

            return Task.FromResult(state);
        }
    }
}