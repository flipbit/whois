using System;
using System.Collections.Generic;
using System.Linq;
using Tokens;

namespace Whois.Parsers.Fixups
{
    /// <summary>
    /// Extracts referential contact details from WHOIS responses
    /// </summary>
    public class WhoisIsocOrgIlFixup : MultipleContactFixup
    {
        public override bool CanFixup(TokenizeResult<WhoisResponse> result)
        {
            // Templates that this Fixup can work on
            return result.Template.Name == "whois.isoc.org.il/il/Found";
        }

        protected override bool TryGetRegistrant(IList<Match> matches, WhoisResponse response, out Contact contact)
        {
            contact = null;

            var contactIdMatch = matches
                .FirstOrDefault(m => m.Token.Name == "Address");

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
                        if (dateTime > response.Updated || !response.Updated.HasValue) response.Updated = dateTime;
                        if (dateTime < response.Registered || !response.Registered.HasValue) response.Registered = dateTime;
                        break;
                }
            }

            return count > 0;
        }

        protected override bool TryGetContact(Contact input, IList<Match> matches, out Contact contact)
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
                        
                    case "Changed":
                        var changedDateTime = (DateTime) match.Value;
                        if (changedDateTime > contact.Created || !contact.Created.HasValue) match.Value = changedDateTime;
                        break;
                }
            }

            return true;
        }
    }
}
