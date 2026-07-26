namespace Whois.Protocols;

/// <summary>
/// Maps internal mutable <see cref="WhoisRecord"/> to public immutable <see cref="DomainInfo"/>.
/// </summary>
internal static class WhoisRecordMapper
{
    public static DomainInfo ToDomainInfo(WhoisRecord record)
    {
        return new DomainInfo
        {
            DomainName = record.DomainName,
            RegistryDomainId = record.RegistryDomainId,
            Status = record.Status,
            DomainStatus = record.DomainStatus.ToList().AsReadOnly(),
            Registered = record.Registered,
            Updated = record.Updated,
            Expiration = record.Expiration,
            Registrar = MapRegistrar(record.Registrar),
            Registrant = MapContact(record.Registrant),
            TechnicalContact = MapContact(record.TechnicalContact),
            AdminContact = MapContact(record.AdminContact),
            BillingContact = MapContact(record.BillingContact),
            ZoneContact = MapContact(record.ZoneContact),
            NameServers = record.NameServers.ToList().AsReadOnly(),
            Remarks = record.Remarks,
            DnsSecStatus = record.DnsSecStatus,
            Trademark = record.Trademark,
        };
    }

    public static LookupDiagnostics ToDiagnostics(WhoisRecord record, string serverUrl, TimeSpan duration, IReadOnlyList<string> referralChain)
    {
        return new LookupDiagnostics
        {
            FieldsParsed = record.FieldsParsed,
            ParsingErrors = record.ParsingErrors,
            TemplateName = record.TemplateName,
            ServerUrl = serverUrl,
            Duration = duration,
            ReferralChain = referralChain,
        };
    }

    private static Registrar? MapRegistrar(WhoisRegistrar? source)
    {
        if (source == null) return null;

        return new Registrar
        {
            Name = source.Name,
            IanaId = source.IanaId,
            Url = source.Url,
            AbuseEmail = source.AbuseEmail,
            AbuseTelephoneNumber = source.AbuseTelephoneNumber,
            WhoisServer = source.WhoisServer,
        };
    }

    private static Contact? MapContact(WhoisContact? source)
    {
        if (source == null) return null;

        return new Contact
        {
            RegistryId = source.RegistryId,
            Name = source.Name,
            Organization = source.Organization,
            Address = MapAddress(source.Address),
            TelephoneNumber = source.TelephoneNumber,
            TelephoneNumberExt = source.TelephoneNumberExt,
            FaxNumber = source.FaxNumber,
            FaxNumberExt = source.FaxNumberExt,
            Email = source.Email,
            Created = source.Created,
            Updated = source.Updated,
        };
    }

    private static Address? MapAddress(IList<string> lines)
    {
        if (lines.Count == 0) return null;

        return new Address
        {
            Lines = lines.ToList().AsReadOnly(),
        };
    }
}
