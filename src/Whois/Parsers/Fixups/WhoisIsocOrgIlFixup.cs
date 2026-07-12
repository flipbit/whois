using Tokens;

namespace Whois.Parsers.Fixups;

/// <summary>
/// Extracts referential contact details from WHOIS responses
/// </summary>
public class WhoisIsocOrgIlFixup : MultipleContactFixup
{
    public override bool CanFixup(TokenizeResult result)
    {
        // Templates that this Fixup can work on
        return string.Equals(result.Template.Name, "whois.isoc.org.il/il/found/01", StringComparison.Ordinal);
    }

    protected override bool TryGetRegistrant(IReadOnlyList<TokenMatch> matches, WhoisResponse response, out Contact? contact)
    {
        contact = null;

        var contactIdMatch = matches
            .FirstOrDefault(m => string.Equals(m.Token.Name, "Address", StringComparison.Ordinal));

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
                    var dateTime = ((DateTimeOffset)match.Value).UtcDateTime;
                    if (dateTime > response.Updated || !response.Updated.HasValue) response.Updated = dateTime;
                    if (dateTime < response.Registered || !response.Registered.HasValue) response.Registered = dateTime;
                    break;
            }
        }

        return count > 0;
    }

    protected override bool TryGetContact(Contact? input, IReadOnlyList<TokenMatch> matches, out Contact? contact)
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

                case "Changed":
                    var changedDateTime = ((DateTimeOffset)match.Value).UtcDateTime;
                    if (changedDateTime > contact.Created || !contact.Created.HasValue) contact.Created = changedDateTime;
                    break;
            }
        }

        return true;
    }
}
