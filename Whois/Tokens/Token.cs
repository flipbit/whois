namespace Whois.Tokens
{
    /// <summary>
    /// Represents a single token in a string
    /// </summary>
    public class Token
    {
        /// <summary>
        /// Gets or sets the prefixed string that must appear before the token.
        /// </summary>
        /// <value>
        /// The prefix.
        /// </value>
        public string Prefix { get; set; }

        /// <summary>
        /// Gets or sets the suffixed string that must appear after the token.
        /// </summary>
        /// <value>
        /// The suffix.
        /// </value>
        public string Suffix { get; set; }

        /// <summary>
        /// Gets or sets the value of the token.
        /// </summary>
        /// <value>
        /// The value.
        /// </value>
        public string Value { get; set; }

        /// <summary>
        /// Determines whether this instance is contained within the given input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public bool ContainedIn(string input)
        {
            return input.Contains(Prefix) && input.Contains(Suffix);
        }
    }
}