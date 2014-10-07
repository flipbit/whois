using System.Collections.Generic;

namespace Whois.Tokens
{
    /// <summary>
    /// Represents a parsed piece of text
    /// </summary>
    public class TokenResult<T>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TokenResult{T}"/> class.
        /// </summary>
        public TokenResult()
        {
            Replacements = new List<Token>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenResult{T}"/> class.
        /// </summary>
        /// <param name="value">The value.</param>
        public TokenResult(T value) : this()
        {
            Value = value;
        }

        /// <summary>
        /// Gets or sets the result of the parsing.
        /// </summary>
        /// <value>
        /// The result.
        /// </value>
        public T Value { get; set; }

        /// <summary>
        /// Gets or sets the number of replacements that where made in the original text.
        /// </summary>
        /// <value>
        /// The replacements.
        /// </value>
        public IList<Token> Replacements { get; set; }
    }
}
