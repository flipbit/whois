using System.Collections.Generic;

namespace Whois.Servers
{
    /// <summary>
    /// Represents an Organization that is responsible for administering a TLD
    /// </summary>
    public class Organization
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Organization"/> class.
        /// </summary>
        public Organization()
        {
            Address = new List<string>();
        }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>
        /// The name.
        /// </value>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the address.
        /// </summary>
        /// <value>
        /// The address.
        /// </value>
        public IList<string> Address { get; set; }
    }
}
