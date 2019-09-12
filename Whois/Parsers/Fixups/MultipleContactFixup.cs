using System;
using System.Collections.Generic;
using System.Linq;
using Tokens;
using Whois.Models;

namespace Whois.Parsers.Fixups
{
    /// <summary>
    /// Extracts referential contact details from WHOIS responses
    /// </summary>
    public class MultipleContactFixup : IFixup
    {
        public bool CanFixup(TokenizeResult<WhoisResponse> result)
        {
            // Templates that this Fixup can work on
            return result.Template.Name == "generic/tld/Found03" || 
                   result.Template.Name == "generic/tld/Found04";
        }

        public void Fixup(TokenizeResult<WhoisResponse> result)
        {
            var response = result.Value;

            if (string.IsNullOrEmpty(response.AdminContact?.RegistryId) == false)
            {
                if (TryGetContact(response.AdminContact.RegistryId, result.Tokens.Matches, out var adminContact))
                {
                    response.AdminContact = adminContact;
                }
            }

            if (string.IsNullOrEmpty(response.TechnicalContact?.RegistryId) == false)
            {
                if (TryGetContact(response.TechnicalContact.RegistryId, result.Tokens.Matches, out var technicalContact))
                {
                    response.TechnicalContact = technicalContact;
                }
            }

            if (string.IsNullOrEmpty(response.ZoneContact?.RegistryId) == false)
            {
                if (TryGetContact(response.ZoneContact.RegistryId, result.Tokens.Matches, out var zoneContact))
                {
                    response.ZoneContact = zoneContact;
                }
            }

            if (string.IsNullOrEmpty(response.BillingContact?.RegistryId) == false)
            {
                if (TryGetContact(response.BillingContact.RegistryId, result.Tokens.Matches, out var billingContact))
                {
                    response.BillingContact = billingContact;
                }
            }

            if (TryGetRegistrant(result.Tokens.Matches, response, out var registrant))
            {
                response.Registrant = registrant;
            }


            return result.Value;
        }

        private bool TryGetRegistrant(IList<Match> matches, WhoisResponse response, out Contact contact)
        {
            contact = null;

            var contactIdMatch = matches
                .FirstOrDefault(m => m.Token.Name == "DomainName");

            if (contactIdMatch == null)
            {
                return false;
            }

            var paragraph = contactIdMatch.Location.Paragraph;

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

                    case "Changed":
                        response.Updated = (DateTime) match.Value;
                        break;

                    case "Created":
                        response.Registered = (DateTime) match.Value;
                        break;
                }
            }

            return count > 0;
        }

        private bool TryGetContact(string contactId, IList<Match> matches, out Contact contact)
        {
            contact = null;

            var contactIdMatch = matches
                .Where(m => m.Token.Name == "Contact.Id")
                .FirstOrDefault(m => string.CompareOrdinal(m.Value.ToString(), contactId) == 0);

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

    }
}
