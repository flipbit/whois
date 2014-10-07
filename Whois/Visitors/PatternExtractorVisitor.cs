using System.Collections.Generic;
using System.Linq;
using System.Text;
using Whois.Domain;
using Whois.Interfaces;
using Whois.Tokens;

namespace Whois.Visitors
{
    /// <summary>
    /// Parses WHOIS data and extracts data into structured objects
    /// </summary>
    public class PatternExtractorVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="MarkMonitorVisitor"/> class.
        /// </summary>
        public PatternExtractorVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MarkMonitorVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public PatternExtractorVisitor(Encoding encoding)
        {
            CurrentEncoding = encoding;
        }

        /// <summary>
        /// Gets all the embdedded patterns in the assembly.
        /// </summary>
        /// <returns></returns>
        public IList<string> GetEmbeddedPatterns()
        {
            var reader = new EmbeddedPatternReader();

            return reader.ReadNamespace(GetType().Assembly, "Whois.Patterns");
        } 

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public WhoisRecord Visit(WhoisRecord record)
        {
            var results = new List<TokenResult<WhoisRecord>>();

            var patterns = GetEmbeddedPatterns();

            foreach (var pattern in patterns)
            {
                var tokenizer = new Tokenizer();

                var clone = record.Clone() as WhoisRecord;

                var result = tokenizer.Parse(clone, pattern, record.AsStrings);

                results.Add(result);
            }

            if (results.Count > 0)
            {
                record = results.OrderBy(r => r.Replacements.Count).First().Value;
            }

            return record;
        }
    }
}