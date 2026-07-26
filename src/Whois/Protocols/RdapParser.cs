using System.Text.Json;

namespace Whois.Protocols;

/// <summary>
/// Parses RFC 9083 RDAP JSON responses into <see cref="DomainInfo"/>.
/// </summary>
internal static class RdapParser
{
    /// <summary>
    /// Parses an RDAP JSON response string into a DomainInfo.
    /// </summary>
    public static DomainInfo Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var domainName = GetString(root, "ldhName");
        var unicodeName = GetString(root, "unicodeName");
        var handle = GetString(root, "handle");

        var statusList = GetStringArray(root, "status");
        var registrationStatus = MapStatus(statusList);

        DateTime? registered = null, updated = null, expiration = null;
        if (root.TryGetProperty("events", out var events))
        {
            foreach (var evt in events.EnumerateArray())
            {
                var action = GetString(evt, "eventAction");
                var dateStr = GetString(evt, "eventDate");
                if (dateStr == null || !DateTime.TryParse(dateStr, provider: null, System.Globalization.DateTimeStyles.RoundtripKind, out var date)) continue;

                switch (action)
                {
                    case "registration": registered = date.ToUniversalTime(); break;
                    case "last changed": updated = date.ToUniversalTime(); break;
                    case "expiration": expiration = date.ToUniversalTime(); break;
                }
            }
        }

        var nameServers = new List<string>();
        if (root.TryGetProperty("nameservers", out var ns))
        {
            foreach (var server in ns.EnumerateArray())
            {
                var name = GetString(server, "ldhName");
                if (name != null) nameServers.Add(name);
            }
        }

        string? dnsSecStatus = null;
        if (root.TryGetProperty("secureDNS", out var secureDns))
        {
            if (secureDns.TryGetProperty("delegationSigned", out var ds))
            {
                dnsSecStatus = ds.GetBoolean() ? "signedDelegation" : "unsigned";
            }
        }

        Registrar? registrar = null;
        Contact? registrant = null, techContact = null, adminContact = null, billingContact = null;

        if (root.TryGetProperty("entities", out var entities))
        {
            foreach (var entity in entities.EnumerateArray())
            {
                var roles = GetStringArray(entity, "roles");

                if (roles.Contains("registrar"))
                {
                    registrar = ParseRegistrar(entity);
                }

                if (roles.Contains("registrant"))
                {
                    registrant = ParseContact(entity);
                }
                else if (roles.Contains("technical"))
                {
                    techContact = ParseContact(entity);
                }
                else if (roles.Contains("administrative"))
                {
                    adminContact = ParseContact(entity);
                }
                else if (roles.Contains("billing"))
                {
                    billingContact = ParseContact(entity);
                }
            }
        }

        string? remarks = null;
        if (root.TryGetProperty("remarks", out var remarksArr))
        {
            var descriptions = new List<string>();
            foreach (var remark in remarksArr.EnumerateArray())
            {
                if (remark.TryGetProperty("description", out var desc))
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
        var name = GetVcardProperty(entity, "fn");
        var handle = GetString(entity, "handle");

        string? abuseEmail = null, abusePhone = null;
        if (entity.TryGetProperty("entities", out var subEntities))
        {
            foreach (var sub in subEntities.EnumerateArray())
            {
                var roles = GetStringArray(sub, "roles");
                if (roles.Contains("abuse"))
                {
                    abuseEmail = GetVcardProperty(sub, "email");
                    abusePhone = GetVcardProperty(sub, "tel");
                }
            }
        }

        string? url = null;
        if (entity.TryGetProperty("links", out var links))
        {
            foreach (var link in links.EnumerateArray())
            {
                var rel = GetString(link, "rel");
                if (rel == "about" || rel == "self")
                {
                    var href = GetString(link, "href");
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
            Name = name,
            IanaId = handle,
            Url = url,
            AbuseEmail = abuseEmail,
            AbuseTelephoneNumber = abusePhone,
        };
    }

    private static Contact ParseContact(JsonElement entity)
    {
        var name = GetVcardProperty(entity, "fn");
        var org = GetVcardProperty(entity, "org");
        var email = GetVcardProperty(entity, "email");
        var phone = GetVcardProperty(entity, "tel");
        var address = ParseJcardAddress(entity);

        return new Contact
        {
            RegistryId = GetString(entity, "handle"),
            Name = name,
            Organization = org,
            Email = email,
            TelephoneNumber = phone,
            Address = address,
        };
    }

    private static Address? ParseJcardAddress(JsonElement entity)
    {
        if (!entity.TryGetProperty("vcardArray", out var vcardArray)) return null;

        var entries = vcardArray.EnumerateArray().ToArray();
        if (entries.Length < 2) return null;

        foreach (var prop in entries[1].EnumerateArray())
        {
            var propArr = prop.EnumerateArray().ToArray();
            if (propArr.Length < 4) continue;
            if (propArr[0].GetString() != "adr") continue;

            // jCard adr value: [PO Box, Extended, Street, City, Region, PostalCode, Country]
            var value = propArr[3];
            if (value.ValueKind != JsonValueKind.Array) continue;

            var parts = value.EnumerateArray().ToArray();
            if (parts.Length < 7) continue;

            var streetVal = parts[2];
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

            var city = parts[3].GetString();
            var region = parts[4].GetString();
            var postalCode = parts[5].GetString();
            var country = parts[6].GetString();

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

        return null;
    }

    private static string? GetVcardProperty(JsonElement entity, string propertyName)
    {
        if (!entity.TryGetProperty("vcardArray", out var vcardArray)) return null;

        var entries = vcardArray.EnumerateArray().ToArray();
        if (entries.Length < 2) return null;

        foreach (var prop in entries[1].EnumerateArray())
        {
            var propArr = prop.EnumerateArray().ToArray();
            if (propArr.Length < 4) continue;
            if (propArr[0].GetString() != propertyName) continue;

            var value = propArr[3];
            return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
        }

        return null;
    }

    private static RegistrationStatus MapStatus(List<string> statuses)
    {
        if (statuses.Count == 0) return RegistrationStatus.Unknown;

        foreach (var status in statuses)
        {
            switch (status)
            {
                case "active": return RegistrationStatus.Found;
                case "inactive": return RegistrationStatus.Inactive;
                case "locked": return RegistrationStatus.Locked;
                case "pending delete": return RegistrationStatus.PendingDelete;
                case "redemption period": return RegistrationStatus.Redemption;
                case "pending create":
                case "pending renew":
                case "pending restore":
                case "pending transfer":
                case "pending update":
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
