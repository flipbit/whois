using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Travel.Travel;

public class TravelParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TravelParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.travel", "travel", "found", "webcams.travel.txt");
        var response = parser.Parse("whois.nic.travel", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.travel/travel/found/01", response.TemplateName);

        Assert.Equal("webcams.travel", response.DomainName.ToString());
        Assert.Equal("D108042-TRAVEL", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("111", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2012, 07, 31, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2006, 08, 01, 12, 39, 21, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2010, 08, 30, 12, 52, 13, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("P-IRO86-YIHZ", response.Registrant.RegistryId);
        Assert.Equal("Ingo Oppermann", response.Registrant.Name);
        Assert.Equal("OPAG Online Promotion AG", response.Registrant.Organization);
        Assert.Equal("+41.442777501", response.Registrant.TelephoneNumber);
        Assert.Equal("+41.763770216", response.Registrant.FaxNumber);
        Assert.Equal("ingo.oppermann@topin.travel", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Austr.37", response.Registrant.Address[0]);
        Assert.Equal("Vaduz", response.Registrant.Address[1]);
        Assert.Equal("9490", response.Registrant.Address[2]);
        Assert.Equal("Liechtenstein", response.Registrant.Address[3]);
        Assert.Equal("LI", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("P-IRO86-YIHZ", response.AdminContact.RegistryId);
        Assert.Equal("Ingo Oppermann", response.AdminContact.Name);
        Assert.Equal("OPAG Online Promotion AG", response.AdminContact.Organization);
        Assert.Equal("+41.442777501", response.AdminContact.TelephoneNumber);
        Assert.Equal("+41.763770216", response.AdminContact.FaxNumber);
        Assert.Equal("ingo.oppermann@topin.travel", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Austr.37", response.AdminContact.Address[0]);
        Assert.Equal("Vaduz", response.AdminContact.Address[1]);
        Assert.Equal("9490", response.AdminContact.Address[2]);
        Assert.Equal("Liechtenstein", response.AdminContact.Address[3]);
        Assert.Equal("LI", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("P-HVO132-PVII", response.BillingContact.RegistryId);
        Assert.Equal("Hans-Peter Oswald", response.BillingContact.Name);
        Assert.Equal("Secura GmbH", response.BillingContact.Organization);
        Assert.Equal("+49.2212571213", response.BillingContact.TelephoneNumber);
        Assert.Equal("+49.221925227", response.BillingContact.FaxNumber);
        Assert.Equal("secura@domainregistry.de", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(6, response.BillingContact.Address.Count);
        Assert.Equal("Frohnhofweg 18", response.BillingContact.Address[0]);
        Assert.Equal("Koeln", response.BillingContact.Address[1]);
        Assert.Equal("NRW", response.BillingContact.Address[2]);
        Assert.Equal("50858", response.BillingContact.Address[3]);
        Assert.Equal("Germany", response.BillingContact.Address[4]);
        Assert.Equal("DE", response.BillingContact.Address[5]);


        // TechnicalContact Details
        Assert.Equal("P-HVO132-PVII", response.TechnicalContact.RegistryId);
        Assert.Equal("Hans-Peter Oswald", response.TechnicalContact.Name);
        Assert.Equal("Secura GmbH", response.TechnicalContact.Organization);
        Assert.Equal("+49.2212571213", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+49.221925227", response.TechnicalContact.FaxNumber);
        Assert.Equal("secura@domainregistry.de", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(6, response.TechnicalContact.Address.Count);
        Assert.Equal("Frohnhofweg 18", response.TechnicalContact.Address[0]);
        Assert.Equal("Koeln", response.TechnicalContact.Address[1]);
        Assert.Equal("NRW", response.TechnicalContact.Address[2]);
        Assert.Equal("50858", response.TechnicalContact.Address[3]);
        Assert.Equal("Germany", response.TechnicalContact.Address[4]);
        Assert.Equal("DE", response.TechnicalContact.Address[5]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("finkployd.nrg4u.com", response.NameServers[0]);
        Assert.Equal("c00l3r.networx.ch", response.NameServers[1]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);

        Assert.Equal(57, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_other_status_single()
    {
        var sample = SampleReader.Read("whois.nic.travel", "travel", "found", "travel.travel.txt");
        var response = parser.Parse("whois.nic.travel", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.travel/travel/found/01", response.TemplateName);

        Assert.Equal("travel.travel", response.DomainName.ToString());
        Assert.Equal("D24096-TRAVEL", response.RegistryDomainId);

        Assert.Equal(new DateTime(2010, 10, 03, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 10, 04, 21, 44, 27, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2006, 07, 23, 16, 08, 37, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("TRALLIANCE", response.Registrant.RegistryId);
        Assert.Equal("Tralliance Corporation", response.Registrant.Name);
        Assert.Equal("+1.9547695999", response.Registrant.TelephoneNumber);
        Assert.Equal("info@tralliance.travel", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(6, response.Registrant.Address.Count);
        Assert.Equal("110 East Broward Blvd, 14th floor", response.Registrant.Address[0]);
        Assert.Equal("Fort Lauderdale", response.Registrant.Address[1]);
        Assert.Equal("FL", response.Registrant.Address[2]);
        Assert.Equal("33301", response.Registrant.Address[3]);
        Assert.Equal("United States", response.Registrant.Address[4]);
        Assert.Equal("US", response.Registrant.Address[5]);


        // AdminContact Details
        Assert.Equal("TRALLIANCE", response.AdminContact.RegistryId);
        Assert.Equal("Tralliance Corporation", response.AdminContact.Name);
        Assert.Equal("+1.9547695999", response.AdminContact.TelephoneNumber);
        Assert.Equal("info@tralliance.travel", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(6, response.AdminContact.Address.Count);
        Assert.Equal("110 East Broward Blvd, 14th floor", response.AdminContact.Address[0]);
        Assert.Equal("Fort Lauderdale", response.AdminContact.Address[1]);
        Assert.Equal("FL", response.AdminContact.Address[2]);
        Assert.Equal("33301", response.AdminContact.Address[3]);
        Assert.Equal("United States", response.AdminContact.Address[4]);
        Assert.Equal("US", response.AdminContact.Address[5]);


        // BillingContact Details
        Assert.Equal("TRALLIANCE", response.BillingContact.RegistryId);
        Assert.Equal("Tralliance Corporation", response.BillingContact.Name);
        Assert.Equal("+1.9547695999", response.BillingContact.TelephoneNumber);
        Assert.Equal("info@tralliance.travel", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(6, response.BillingContact.Address.Count);
        Assert.Equal("110 East Broward Blvd, 14th floor", response.BillingContact.Address[0]);
        Assert.Equal("Fort Lauderdale", response.BillingContact.Address[1]);
        Assert.Equal("FL", response.BillingContact.Address[2]);
        Assert.Equal("33301", response.BillingContact.Address[3]);
        Assert.Equal("United States", response.BillingContact.Address[4]);
        Assert.Equal("US", response.BillingContact.Address[5]);


        // TechnicalContact Details
        Assert.Equal("TRALLIANCE", response.TechnicalContact.RegistryId);
        Assert.Equal("Tralliance Corporation", response.TechnicalContact.Name);
        Assert.Equal("+1.9547695999", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("info@tralliance.travel", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(6, response.TechnicalContact.Address.Count);
        Assert.Equal("110 East Broward Blvd, 14th floor", response.TechnicalContact.Address[0]);
        Assert.Equal("Fort Lauderdale", response.TechnicalContact.Address[1]);
        Assert.Equal("FL", response.TechnicalContact.Address[2]);
        Assert.Equal("33301", response.TechnicalContact.Address[3]);
        Assert.Equal("United States", response.TechnicalContact.Address[4]);
        Assert.Equal("US", response.TechnicalContact.Address[5]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("netsys.com", response.NameServers[0]);
        Assert.Equal("ns01-mia.theglobe.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(49, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.travel", "travel", "not-found", "u34jedzcq.travel.txt");
        var response = parser.Parse("whois.nic.travel", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.travel/travel/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.travel", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.travel", "travel", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.travel", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.travel/travel/found/01", response.TemplateName);

        Assert.Equal("travel.travel", response.DomainName.ToString());
        Assert.Equal("D24096-TRAVEL", response.RegistryDomainId);

        Assert.Equal(new DateTime(2021, 10, 03, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 10, 04, 21, 44, 27, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 09, 18, 15, 13, 32, 000, DateTimeKind.Utc), response.Expiration);

        // Registrar Details
        Assert.Equal("whois.neustar.us", response.Registrar.Url);

        // Registrant Details
        Assert.Equal("TRALLIANCE", response.Registrant.RegistryId);
        Assert.Equal("Tralliance Corporation", response.Registrant.Name);
        Assert.Equal("+1.9547695999", response.Registrant.TelephoneNumber);
        Assert.Equal("info@tralliance.travel", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(6, response.Registrant.Address.Count);
        Assert.Equal("110 East Broward Blvd, 14th floor", response.Registrant.Address[0]);
        Assert.Equal("Fort Lauderdale", response.Registrant.Address[1]);
        Assert.Equal("FL", response.Registrant.Address[2]);
        Assert.Equal("33301", response.Registrant.Address[3]);
        Assert.Equal("United States", response.Registrant.Address[4]);
        Assert.Equal("US", response.Registrant.Address[5]);


        // AdminContact Details
        Assert.Equal("TRALLIANCE", response.AdminContact.RegistryId);
        Assert.Equal("Tralliance Corporation", response.AdminContact.Name);
        Assert.Equal("+1.9547695999", response.AdminContact.TelephoneNumber);
        Assert.Equal("info@tralliance.travel", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(6, response.AdminContact.Address.Count);
        Assert.Equal("110 East Broward Blvd, 14th floor", response.AdminContact.Address[0]);
        Assert.Equal("Fort Lauderdale", response.AdminContact.Address[1]);
        Assert.Equal("FL", response.AdminContact.Address[2]);
        Assert.Equal("33301", response.AdminContact.Address[3]);
        Assert.Equal("United States", response.AdminContact.Address[4]);
        Assert.Equal("US", response.AdminContact.Address[5]);


        // BillingContact Details
        Assert.Equal("TRALLIANCE", response.BillingContact.RegistryId);
        Assert.Equal("Tralliance Corporation", response.BillingContact.Name);
        Assert.Equal("+1.9547695999", response.BillingContact.TelephoneNumber);
        Assert.Equal("info@tralliance.travel", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(6, response.BillingContact.Address.Count);
        Assert.Equal("110 East Broward Blvd, 14th floor", response.BillingContact.Address[0]);
        Assert.Equal("Fort Lauderdale", response.BillingContact.Address[1]);
        Assert.Equal("FL", response.BillingContact.Address[2]);
        Assert.Equal("33301", response.BillingContact.Address[3]);
        Assert.Equal("United States", response.BillingContact.Address[4]);
        Assert.Equal("US", response.BillingContact.Address[5]);


        // TechnicalContact Details
        Assert.Equal("TRALLIANCE", response.TechnicalContact.RegistryId);
        Assert.Equal("Tralliance Corporation", response.TechnicalContact.Name);
        Assert.Equal("+1.9547695999", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("info@tralliance.travel", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(6, response.TechnicalContact.Address.Count);
        Assert.Equal("110 East Broward Blvd, 14th floor", response.TechnicalContact.Address[0]);
        Assert.Equal("Fort Lauderdale", response.TechnicalContact.Address[1]);
        Assert.Equal("FL", response.TechnicalContact.Address[2]);
        Assert.Equal("33301", response.TechnicalContact.Address[3]);
        Assert.Equal("United States", response.TechnicalContact.Address[4]);
        Assert.Equal("US", response.TechnicalContact.Address[5]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns01-mia.theglobe.com", response.NameServers[0]);
        Assert.Equal("netsys.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(50, response.FieldsParsed);
    }
}
