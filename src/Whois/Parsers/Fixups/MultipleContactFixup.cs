using System;
using System.Collections.Generic;
using System.Linq;
using Tokens;

namespace Whois.Parsers.Fixups
{
    /// <summary>
    /// Extracts referential contact details from WHOIS responses
    /// </summary>
    public class MultipleContactFixup : IFixup
    {
        public virtual bool CanFixup(TokenizeResult<WhoisResponse> result)
        {
            if (result.Template.HasTag("fixup-contact"))
            {
                return true;
            }

            // Templates that this Fixup can work on
            return result.Template.Name == "generic/tld/Found03" || 
                   result.Template.Name == "generic/tld/Found04" || 
                   result.Template.Name == "whois.nic.at/at/Found";
        }

        public void Fixup(TokenizeResult<WhoisResponse> result)
        {
            var response = result.Value;

            if (TryGetRegistrant(result.Tokens.Matches, response, out var registrant))
            {
                response.Registrant = registrant;
            }

            // Lookup Ids
            if (TryGetContactId(response.AdminContact, result.Tokens.Matches, "admin", out var adminContactId))
            {
                response.AdminContact = new Contact { RegistryId = adminContactId };
            }

            if (TryGetContactId(response.Registrant, result.Tokens.Matches, "registrant", out var registrantId))
            {
                response.Registrant = new Contact { RegistryId = registrantId };
            }

            if (TryGetContactId(response.BillingContact, result.Tokens.Matches, "billing", out var billingContactId))
            {
                response.BillingContact = new Contact { RegistryId = billingContactId };
            }

            if (TryGetContactId(response.TechnicalContact, result.Tokens.Matches, "tech", out var techContactId))
            {
                response.TechnicalContact = new Contact { RegistryId = techContactId };
            }

            if (TryGetContact(response.AdminContact, result.Tokens.Matches, out var adminContact))
            {
                response.AdminContact = adminContact;
            }

            if (TryGetContact(response.TechnicalContact, result.Tokens.Matches, out var technicalContact))
            {
                response.TechnicalContact = technicalContact;
            }

            if (TryGetContact(response.ZoneContact, result.Tokens.Matches, out var zoneContact))
            {
                response.ZoneContact = zoneContact;
            }

            if (TryGetContact(response.BillingContact, result.Tokens.Matches, out var billingContact))
            {
                response.BillingContact = billingContact;
            }

            if (TryGetContact(response.Registrant, result.Tokens.Matches, out var registrantContact))
            {
                response.Registrant = registrantContact;
            }
        }

        protected virtual int? GetRegistrantParagraph(IList<Match> matches)
        {
            var contactIdMatch = matches
                .FirstOrDefault(m => m.Token.Name == "DomainName");

            return contactIdMatch?.Location.Paragraph;
        }

        protected virtual bool TryGetRegistrant(IList<Match> matches, WhoisResponse response, out Contact contact)
        {
            contact = null;

            var paragraph = GetRegistrantParagraph(matches);

            if (paragraph.HasValue == false) return false;

            contact = new Contact();
            var count = 0;

            foreach (var match in matches)
            {
                if (match.Location.Paragraph != paragraph) continue;

                switch (match.Token.Name)
                {
                    case "Address":
                        var matchValueString = match.Value.ToString();
                        if (string.IsNullOrEmpty(contact.Name))
                        {
                            contact.Name = matchValueString;
                        }
                        else
                        {
                            contact.Address.Add(matchValueString);
                        }
                        count++;
                        break;

                    case "Phone":
                        contact.TelephoneNumber = match.Value.ToString();
                        break;

                    case "Fax":
                        contact.FaxNumber = match.Value.ToString();
                        break;
                        
                    case "Email":
                        contact.Email = match.Value.ToString();
                        break;

                    case "Changed":
                        var dateTime = (DateTime) match.Value;
                        if (dateTime > response.Updated || 
                            !response.Updated.HasValue) response.Updated = dateTime;
                        break;

                    case "Created":
                        response.Registered = (DateTime) match.Value;
                        break;
                }
            }

            return count > 0;
        }

        protected virtual bool TryGetContact(Contact input, IList<Match> matches, out Contact contact)
        {
            contact = null;

            if (string.IsNullOrEmpty(input?.RegistryId)) return false;

            var contactIdMatch = matches
                .Where(m => m.Token.Name == "Contact.Id")
                .FirstOrDefault(m => string.CompareOrdinal(m.Value.ToString(), input.RegistryId) == 0);

            if (contactIdMatch == null)
            {
                return false;
            }

            var paragraph = contactIdMatch.Location.Paragraph;

            contact = new Contact();

            foreach (var match in matches)
            {
                if (match.Location.Paragraph != paragraph) continue;

                switch (match.Token.Name)
                {
                    case "Contact.Name":
                        contact.Name = match.Value.ToString();
                        break;

                    case "Contact.Organization":
                        contact.Organization = match.Value.ToString();
                        break;

                    case "Contact.Id":
                        contact.RegistryId = match.Value.ToString();
                        break;

                    case "Address":
                        contact.Address.Add(match.Value.ToString());
                        break;

                    case "Phone":
                        contact.TelephoneNumber = match.Value.ToString();
                        break;

                    case "Fax":
                        contact.FaxNumber = match.Value.ToString();
                        break;
                        
                    case "Email":
                        contact.Email = match.Value.ToString();
                        break;
                        
                    case "Created":
                        contact.Created = (DateTime) match.Value;
                        break;
                }
            }

            return true;
        }

        protected virtual bool TryGetContactId(Contact input, IList<Match> matches, string name, out string contactId)
        {
            contactId = null;

            if (input != null) return false;

            var paragraph = matches
                .Where(m => m.Token.Name == "Type")
                .FirstOrDefault(m => string.CompareOrdinal(m.Value.ToString(), name) == 0)?
                .Location.Paragraph;

            if (paragraph == null) return false;

            var match = matches
                .Where(m => m.Token.Name == "Contact.Id")
                .Where(m => m.Location.Paragraph == paragraph.Value)
                .FirstOrDefault();

            if (match == null) return false;

            contactId = match.Value.ToString();

            return true;
        }
    }
}
