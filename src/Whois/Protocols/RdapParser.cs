using System.Text.Json;

namespace Whois.Protocols;

/// <summary>
/// Parses RFC 9083 RDAP JSON responses into <see cref="DomainInfo"/>.
/// </summary>
/// <remarks>
/// Pure static design: no logger or state. Unrecognized or malformed fields
/// are skipped via null checks and TryGetProperty. JsonDocument.Parse exceptions
/// propagate to callers (no error suppression).
/// </remarks>
internal static class RdapParser
{
    // RFC 9083 JSON property names
    private const string PropLdhName = "ldhName";
    private const string PropUnicodeName = "unicodeName";
    private const string PropHandle = "handle";
    private const string PropStatus = "status";
    private const string PropEvents = "events";
    private const string PropEventAction = "eventAction";
    private const string PropEventDate = "eventDate";
    private const string PropNameservers = "nameservers";
    private const string PropSecureDns = "secureDNS";
    private const string PropDelegationSigned = "delegationSigned";
    private const string PropEntities = "entities";
    private const string PropRoles = "roles";
    private const string PropVcardArray = "vcardArray";
    private const string PropRemarks = "remarks";
    private const string PropDescription = "description";
    private const string PropLinks = "links";
    private const string PropRel = "rel";
    private const string PropHref = "href";

    // RFC 9083 event action values
    private const string EventRegistration = "registration";
    private const string EventLastChanged = "last changed";
    private const string EventExpiration = "expiration";

    // RFC 9083 entity role values
    private const string RoleRegistrar = "registrar";
    private const string RoleRegistrant = "registrant";
    private const string RoleTechnical = "technical";
    private const string RoleAdministrative = "administrative";
    private const string RoleBilling = "billing";
    private const string RoleAbuse = "abuse";

    // RFC 9083 status values
    private const string StatusActive = "active";
    private const string StatusInactive = "inactive";
    private const string StatusLocked = "locked";
    private const string StatusPendingDelete = "pending delete";
    private const string StatusRedemptionPeriod = "redemption period";
    private const string StatusPendingCreate = "pending create";
    private const string StatusPendingRenew = "pending renew";
    private const string StatusPendingRestore = "pending restore";
    private const string StatusPendingTransfer = "pending transfer";
    private const string StatusPendingUpdate = "pending update";

    // DNSSEC status strings
    private const string DnsSecSigned = "signedDelegation";
    private const string DnsSecUnsigned = "unsigned";

    // Link relation values
    private const string RelAbout = "about";
    private const string RelSelf = "self";

    // jCard (RFC 7095) property names
    private const string VcardFn = "fn";
    private const string VcardOrg = "org";
    private const string VcardEmail = "email";
    private const string VcardTel = "tel";
    private const string VcardAdr = "adr";

    // jCard adr value array indices per RFC 6350 (Section 6.3.1):
    // [PO Box, Extended, Street, City, Region, PostalCode, Country]
    private const int JCardAdrStreet = 2;
    private const int JCardAdrCity = 3;
    private const int JCardAdrRegion = 4;
    private const int JCardAdrPostalCode = 5;
    private const int JCardAdrCountry = 6;
    private const int JCardAdrMinLength = 7;

    // Minimum element counts for jCard structure
    private const int MinVCardArrayEntries = 2;
    private const int MinVCardPropertyElements = 4;

    /// <summary>
    /// Parses an RDAP JSON response string into a DomainInfo.
    /// </summary>
    public static DomainInfo Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var domainName = GetString(root, PropLdhName);
        var unicodeName = GetString(root, PropUnicodeName);
        var handle = GetString(root, PropHandle);

        var statusList = GetStringArray(root, PropStatus);
        var registrationStatus = MapStatus(statusList);

        DateTime? registered = null, updated = null, expiration = null;
        if (root.TryGetProperty(PropEvents, out var events))
        {
            foreach (var evt in events.EnumerateArray())
            {
                var action = GetString(evt, PropEventAction);
                var dateStr = GetString(evt, PropEventDate);
                if (dateStr == null || !DateTime.TryParse(dateStr, provider: null, System.Globalization.DateTimeStyles.RoundtripKind, out var date)) continue;

                switch (action)
                {
                    case EventRegistration: registered = date.ToUniversalTime(); break;
                    case EventLastChanged: updated = date.ToUniversalTime(); break;
                    case EventExpiration: expiration = date.ToUniversalTime(); break;
                }
            }
        }

        var nameServers = new List<string>();
        if (root.TryGetProperty(PropNameservers, out var ns))
        {
            foreach (var server in ns.EnumerateArray())
            {
                var name = GetString(server, PropLdhName);
                if (name != null) nameServers.Add(name);
            }
        }

        string? dnsSecStatus = null;
        if (root.TryGetProperty(PropSecureDns, out var secureDns))
        {
            if (secureDns.TryGetProperty(PropDelegationSigned, out var ds))
            {
                dnsSecStatus = ds.GetBoolean() ? DnsSecSigned : DnsSecUnsigned;
            }
        }

        Registrar? registrar = null;
        Contact? registrant = null, techContact = null, adminContact = null, billingContact = null;

        if (root.TryGetProperty(PropEntities, out var entities))
        {
            foreach (var entity in entities.EnumerateArray())
            {
                var roles = GetStringArray(entity, PropRoles);

                if (roles.Contains(RoleRegistrar))
                {
                    registrar = ParseRegistrar(entity);
                }

                if (roles.Contains(RoleRegistrant))
                {
                    registrant = ParseContact(entity);
                }
                if (roles.Contains(RoleTechnical))
                {
                    techContact = ParseContact(entity);
                }
                if (roles.Contains(RoleAdministrative))
                {
                    adminContact = ParseContact(entity);
                }
                if (roles.Contains(RoleBilling))
                {
                    billingContact = ParseContact(entity);
                }
            }
        }

        string? remarks = null;
        if (root.TryGetProperty(PropRemarks, out var remarksArr))
        {
            var descriptions = new List<string>();
            foreach (var remark in remarksArr.EnumerateArray())
            {
                if (remark.TryGetProperty(PropDescription, out var desc))
                {
                    foreach (var line in desc.EnumerateArray())
                    {
                        var s = line.GetString();
                        if (s != null) descriptions.Add(s);
                    }
                }
            }
#pragma warning disable MA0089 // string.Join(char) overload not available on netstandard2.0
            if (descriptions.Count > 0) remarks = string.Join("\n", descriptions);
#pragma warning restore MA0089
        }

        HostName? parsedDomainName = null;
        var nameToUse = domainName ?? unicodeName;
        if (nameToUse != null) HostName.TryParse(nameToUse, out parsedDomainName);

        return new DomainInfo
        {
            DomainName = parsedDomainName,
            RegistryDomainId = handle,
            Status = registrationStatus,
            DomainStatus = statusList.AsReadOnly(),
            Registered = registered,
            Updated = updated,
            Expiration = expiration,
            Registrar = registrar,
            Registrant = registrant,
            TechnicalContact = techContact,
            AdminContact = adminContact,
            BillingContact = billingContact,
            NameServers = nameServers.AsReadOnly(),
            DnsSecStatus = dnsSecStatus,
            Remarks = remarks,
        };
    }

    private static Registrar ParseRegistrar(JsonElement entity)
    {
        var vcard = ExtractVCardProperties(entity);
        var handle = GetString(entity, PropHandle);

        string? abuseEmail = null, abusePhone = null;
        if (entity.TryGetProperty(PropEntities, out var subEntities))
        {
            foreach (var sub in subEntities.EnumerateArray())
            {
                var roles = GetStringArray(sub, PropRoles);
                if (roles.Contains(RoleAbuse))
                {
                    var abuseVcard = ExtractVCardProperties(sub);
                    abuseEmail = abuseVcard.Email;
                    abusePhone = abuseVcard.Tel;
                }
            }
        }

        string? url = null;
        if (entity.TryGetProperty(PropLinks, out var links))
        {
            foreach (var link in links.EnumerateArray())
            {
                var rel = GetString(link, PropRel);
                if (rel == RelAbout || rel == RelSelf)
                {
                    var href = GetString(link, PropHref);
                    if (href != null)
                    {
                        url = href;
                        break;
                    }
                }
            }
        }

        return new Registrar
        {
            Name = vcard.Fn,
            IanaId = handle,
            Url = url,
            AbuseEmail = abuseEmail,
            AbuseTelephoneNumber = abusePhone,
        };
    }

    private static Contact ParseContact(JsonElement entity)
    {
        var vcard = ExtractVCardProperties(entity);

        return new Contact
        {
            RegistryId = GetString(entity, PropHandle),
            Name = vcard.Fn,
            Organization = vcard.Org,
            Email = vcard.Email,
            TelephoneNumber = vcard.Tel,
            Address = vcard.Address,
        };
    }

    /// <summary>
    /// Iterates the jCard property array once, extracting all needed properties
    /// (fn, org, email, tel, adr) in a single pass.
    /// </summary>
    private static (string? Fn, string? Org, string? Email, string? Tel, Address? Address)
        ExtractVCardProperties(JsonElement entity)
    {
        if (!entity.TryGetProperty(PropVcardArray, out var vcardArray))
            return default;

        var entries = vcardArray.EnumerateArray().ToArray();
        if (entries.Length < MinVCardArrayEntries)
            return default;

        string? fn = null, org = null, email = null, tel = null;
        Address? address = null;

        foreach (var prop in entries[1].EnumerateArray())
        {
            var propArr = prop.EnumerateArray().ToArray();
            if (propArr.Length < MinVCardPropertyElements) continue;

            var propName = propArr[0].GetString();
            var value = propArr[3];

            switch (propName)
            {
                case VcardFn:
                    fn ??= value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
                    break;
                case VcardOrg:
                    org ??= value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
                    break;
                case VcardEmail:
                    email ??= value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
                    break;
                case VcardTel:
                    tel ??= value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
                    break;
                case VcardAdr:
                    address ??= ParseAdrValue(value);
                    break;
            }
        }

        return (fn, org, email, tel, address);
    }

    private static Address? ParseAdrValue(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array) return null;

        var parts = value.EnumerateArray().ToArray();
        if (parts.Length < JCardAdrMinLength) return null;

        var streetVal = parts[JCardAdrStreet];
        List<string>? streetLines = null;
        if (streetVal.ValueKind == JsonValueKind.Array)
        {
            streetLines = new List<string>();
            foreach (var line in streetVal.EnumerateArray())
            {
                var s = line.GetString();
                if (!string.IsNullOrWhiteSpace(s)) streetLines.Add(s!);
            }
            if (streetLines.Count == 0) streetLines = null;
        }
        else if (streetVal.ValueKind == JsonValueKind.String)
        {
            var s = streetVal.GetString();
            if (!string.IsNullOrWhiteSpace(s)) streetLines = [s!];
        }

        var city = parts[JCardAdrCity].GetString();
        var region = parts[JCardAdrRegion].GetString();
        var postalCode = parts[JCardAdrPostalCode].GetString();
        var country = parts[JCardAdrCountry].GetString();

        var lines = new List<string>();
        if (streetLines != null) lines.AddRange(streetLines);
        if (!string.IsNullOrWhiteSpace(city)) lines.Add(city!);
        if (!string.IsNullOrWhiteSpace(region)) lines.Add(region!);
        if (!string.IsNullOrWhiteSpace(postalCode)) lines.Add(postalCode!);
        if (!string.IsNullOrWhiteSpace(country)) lines.Add(country!);

        if (lines.Count == 0) return null;

        return new Address
        {
            Lines = lines.AsReadOnly(),
            Street = streetLines?.AsReadOnly(),
            City = string.IsNullOrWhiteSpace(city) ? null : city,
            Region = string.IsNullOrWhiteSpace(region) ? null : region,
            PostalCode = string.IsNullOrWhiteSpace(postalCode) ? null : postalCode,
            Country = string.IsNullOrWhiteSpace(country) ? null : country,
        };
    }

    private static RegistrationStatus MapStatus(List<string> statuses)
    {
        if (statuses.Count == 0) return RegistrationStatus.Unknown;

        foreach (var status in statuses)
        {
            switch (status)
            {
                case StatusActive: return RegistrationStatus.Found;
                case StatusInactive: return RegistrationStatus.Inactive;
                case StatusLocked: return RegistrationStatus.Locked;
                case StatusPendingDelete: return RegistrationStatus.PendingDelete;
                case StatusRedemptionPeriod: return RegistrationStatus.Redemption;
                case StatusPendingCreate:
                case StatusPendingRenew:
                case StatusPendingRestore:
                case StatusPendingTransfer:
                case StatusPendingUpdate:
                    return RegistrationStatus.Other;
            }
        }

        // Non-empty status list with no specific match means domain exists (e.g. EPP lock codes)
        return RegistrationStatus.Found;
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;
    }

    private static List<string> GetStringArray(JsonElement element, string propertyName)
    {
        var result = new List<string>();
        if (!element.TryGetProperty(propertyName, out var arr) || arr.ValueKind != JsonValueKind.Array)
            return result;

        foreach (var item in arr.EnumerateArray())
        {
            var s = item.GetString();
            if (s != null) result.Add(s);
        }

        return result;
    }
}
