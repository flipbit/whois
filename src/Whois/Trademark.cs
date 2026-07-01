using System;

namespace Whois
{
    /// <summary>
    /// Represents Trademark information embedded in a <see cref="WhoisResponse"/>.
    /// </summary>
    public class Trademark
    {
        /// <summary>
        /// The Trademark Name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The date of the Trademark
        /// </summary>
        public DateTime Date { get; set; }

        /// <summary>
        /// The country where the Trademark is registered
        /// </summary>
        public string Country { get; set; }

        /// <summary>
        /// The Trademark number
        /// </summary>
        public int Number { get; set; }
    }
}
