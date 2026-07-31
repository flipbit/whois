using Tokens;
using Whois.Protocols;

namespace Whois.Parsers.Fixups;

/// <summary>
/// Extracts referential contact details from WHOIS responses
/// </summary>
internal class MultipleContactFixup : IFixup
{
    public virtual bool CanFixup(TokenizeResult result)
    {
        if (result.Template.HasTag("fixup-contact"))
        {
            return true;
        }

        // Templates that this Fixup can work on
        return string.Equals(result.Template.Name, "generic/tld/found/03", StringComparison.Ordinal) ||
               string.Equals(result.Template.Name, "generic/tld/found/04", StringComparison.Ordinal) ||
               string.Equals(result.Template.Name, "whois.nic.at/at/found/01", StringComparison.Ordinal);
    }

    public void Fixup(TokenizeResult result, WhoisRecord record)
    {
        if (TryGetRegistrant(result.Tokens.Matches, record, out var registrant))
        {
            record.Registrant = registrant;
        }

        // Lookup Ids
        if (TryGetContactId(record.AdminContact, result.Tokens.Matches, "admin", out var adminContactId))
        {
            record.AdminContact = new WhoisContact { RegistryId = adminContactId };
        }

        if (TryGetContactId(record.Registrant, result.Tokens.Matches, "registrant", out var registrantId))
        {
            record.Registrant = new WhoisContact { RegistryId = registrantId };
        }

        if (TryGetContactId(record.BillingContact, result.Tokens.Matches, "billing", out var billingContactId))
        {
            record.BillingContact = new WhoisContact { RegistryId = billingContactId };
        }

        if (TryGetContactId(record.TechnicalContact, result.Tokens.Matches, "tech", out var techContactId))
        {
            record.TechnicalContact = new WhoisContact { RegistryId = techContactId };
        }

        if (TryGetContact(record.AdminContact, result.Tokens.Matches, out var adminContact))
        {
            record.AdminContact = adminContact;
        }

        if (TryGetContact(record.TechnicalContact, result.Tokens.Matches, out var technicalContact))
        {
            record.TechnicalContact = technicalContact;
        }

        if (TryGetContact(record.ZoneContact, result.Tokens.Matches, out var zoneContact))
        {
            record.ZoneContact = zoneContact;
        }

        if (TryGetContact(record.BillingContact, result.Tokens.Matches, out var billingContact))
        {
            record.BillingContact = billingContact;
        }

        if (TryGetContact(record.Registrant, result.Tokens.Matches, out var registrantContact))
        {
            record.Registrant = registrantContact;
        }
    }

    protected virtual int? GetRegistrantParagraph(IReadOnlyList<TokenMatch> matches)
    {
        var contactIdMatch = matches
            .FirstOrDefault(m => string.Equals(m.Token.Name, "DomainName", StringComparison.Ordinal));

        return contactIdMatch?.Location.Paragraph;
    }

    protected virtual bool TryGetRegistrant(IReadOnlyList<TokenMatch> matches, WhoisRecord record, out WhoisContact? contact)
    {
        contact = null;

        var paragraph = GetRegistrantParagraph(matches);

        if (!paragraph.HasValue) return false;

        contact = new WhoisContact();
        var count = 0;

        foreach (var match in matches)
        {
            if (match.Location.Paragraph != paragraph) continue;

            switch (match.Token.Name)
            {
                case "Address":
                    var matchValueString = match.Value.ToString() ?? string.Empty;
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
                    var changedDto = (DateTimeOffset)match.Value;
                    var dateTime = changedDto.UtcDateTime;
                    if (dateTime > record.Updated ||
                        !record.Updated.HasValue) record.Updated = dateTime;
                    break;

                case "Created":
                    record.Registered = ((DateTimeOffset)match.Value).UtcDateTime;
                    break;
            }
        }

        return count > 0;
    }

    protected virtual bool TryGetContact(WhoisContact? input, IReadOnlyList<TokenMatch> matches, out WhoisContact? contact)
    {
        contact = null;

        if (string.IsNullOrEmpty(input?.RegistryId)) return false;

        var contactIdMatch = matches
            .FirstOrDefault(m => string.Equals(m.Token.Name, "Contact.Id", StringComparison.Ordinal) &&
                                 string.Equals(m.Value.ToString(), input!.RegistryId, StringComparison.Ordinal));

        if (contactIdMatch == null)
        {
            return false;
        }

        var paragraph = contactIdMatch.Location.Paragraph;

        contact = new WhoisContact();

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
                    contact.Address.Add(match.Value.ToString() ?? string.Empty);
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
                    contact.Created = ((DateTimeOffset)match.Value).UtcDateTime;
                    break;
            }
        }

        return true;
    }

    protected virtual bool TryGetContactId(WhoisContact? input, IReadOnlyList<TokenMatch> matches, string name, out string? contactId)
    {
        contactId = null;

        if (input != null) return false;

        var paragraph = matches
            .FirstOrDefault(m => string.Equals(m.Token.Name, "Type", StringComparison.Ordinal) &&
                                 string.Equals(m.Value.ToString(), name, StringComparison.Ordinal))?
            .Location.Paragraph;

        if (paragraph == null) return false;

        var match = matches
            .FirstOrDefault(m => string.Equals(m.Token.Name, "Contact.Id", StringComparison.Ordinal) &&
                                 m.Location.Paragraph == paragraph.Value);

        if (match == null) return false;

        contactId = match.Value.ToString();

        return true;
    }
}
