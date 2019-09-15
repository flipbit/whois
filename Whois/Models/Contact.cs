using System;
using System.Collections.Generic;

namespace Whois.Models
{
    /// <summary>
    /// Represents a contact who is responsible for administering a TLD
    /// </summary>
    public class Contact
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Contact"/> class.
        /// </summary>
        public Contact()
        {
            Address = new List<string>();
        }

        public string RegistryId { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>
        /// The name.
        /// </value>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the organization.
        /// </summary>
        /// <value>
        /// The organisation.
        /// </value>
        public string Organization { get; set; }

        /// <summary>
        /// Gets or sets the address.
        /// </summary>
        /// <value>
        /// The address.
        /// </value>
        public IList<string> Address { get; private set; }

        /// <summary>
        /// Gets or sets the telephone number.
        /// </summary>
        /// <value>
        /// The telephone number.
        /// </value>
        public string TelephoneNumber { get; set; }

        public string TelephoneNumberExt { get; set; }

        /// <summary>
        /// Gets or sets the fax number.
        /// </summary>
        /// <value>
        /// The fax number.
        /// </value>
        public string FaxNumber { get; set; }

        public string FaxNumberExt { get; set; }

        /// <summary>
        /// Gets or sets the email.
        /// </summary>
        /// <value>
        /// The email.
        /// </value>
        public string Email { get; set; }

        public DateTime? Created { get; set; }

        public DateTime? Updated { get; set; }
    }
}
