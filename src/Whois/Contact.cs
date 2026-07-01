using System;
using System.Collections.Generic;

namespace Whois
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

        /// <summary>
        /// The Registrars Id for this contact
        /// </summary>
        public string RegistryId { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the organization.
        /// </summary>
        public string Organization { get; set; }

        /// <summary>
        /// Gets or sets the address.
        /// </summary>
        public IList<string> Address { get; }

        /// <summary>
        /// Gets or sets the telephone number.
        /// </summary>
        public string TelephoneNumber { get; set; }

        /// <summary>
        /// The Telephone Number extenstion.
        /// </summary>
        public string TelephoneNumberExt { get; set; }

        /// <summary>
        /// Gets or sets the fax number.
        /// </summary>
        public string FaxNumber { get; set; }

        /// <summary>
        /// The Fax Number Extension.
        /// </summary>
        public string FaxNumberExt { get; set; }

        /// <summary>
        /// Gets or sets the email.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// The date the contact was created, if available.
        /// </summary>
        public DateTime? Created { get; set; }

        /// <summary>
        /// The date the contact was last updated, if available.
        /// </summary>
        public DateTime? Updated { get; set; }
    }
}
