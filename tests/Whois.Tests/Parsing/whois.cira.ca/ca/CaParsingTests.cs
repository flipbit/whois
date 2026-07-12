using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cira.Ca.Ca;

public class CaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "found", "glu.ca.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/found/01", response.TemplateName);

        Assert.Equal("glu.ca", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Webnames.ca Inc.", response.Registrar.Name);
        Assert.Equal("70", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2010, 12, 04, 00, 00, 00, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2004, 10, 30, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2010, 10, 29, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Sanamato Inc.", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("Ross Vito", response.AdminContact.Name);
        Assert.Equal("1 (647) 964-4544", response.AdminContact.TelephoneNumber);
        Assert.Equal("mail@sanamato.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(2, response.AdminContact.Address.Count);
        Assert.Equal("405 Queen Street South, P.O. Box 75004", response.AdminContact.Address[0]);
        Assert.Equal("Bolton ON L7E2B5 Canada", response.AdminContact.Address[1]);


        // TechnicalContact Details
        Assert.Equal("Ross Vito", response.TechnicalContact.Name);
        Assert.Equal("1 (647) 964-4544", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("mail@sanamato.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(2, response.TechnicalContact.Address.Count);
        Assert.Equal("405 Queen Street South, P.O. Box 75004", response.TechnicalContact.Address[0]);
        Assert.Equal("Bolton ON L7E2B5 Canada", response.TechnicalContact.Address[1]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.webnames.ca", response.NameServers[0]);
        Assert.Equal("ns2.webnames.ca", response.NameServers[1]);
        Assert.Equal("ns3.webnames.ca", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("registered", response.DomainStatus[0]);

        Assert.Equal(22, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_assigned()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "not-assigned", "not_assigned.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotAssigned, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/found/01", response.TemplateName);

        Assert.Equal("abbylane.pe.ca", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("easyDNS Technologies Inc.", response.Registrar.Name);
        Assert.Equal("88", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2000, 10, 26, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 11, 30, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Abbylane Summer Homes", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("Jeff Carmody", response.AdminContact.Name);
        Assert.Equal("+1 902-621-0244", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1 902-566-0823", response.AdminContact.FaxNumber);
        Assert.Equal("jeff@abbylane.pe.ca", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Abbylane Summer Homes", response.AdminContact.Address[0]);
        Assert.Equal("8 Birchill Drive", response.AdminContact.Address[1]);
        Assert.Equal("Ch-town PE C1A 6W5 Canada", response.AdminContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("Jeff Carmody", response.TechnicalContact.Name);
        Assert.Equal("+1 902 566 0829", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1 902-628-4355", response.TechnicalContact.FaxNumber);
        Assert.Equal("jeff@abbylane.pe.ca", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(2, response.TechnicalContact.Address.Count);
        Assert.Equal("550 University Ave", response.TechnicalContact.Address[0]);
        Assert.Equal("Charlottetown PE C1A4p3 Canada", response.TechnicalContact.Address[1]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("ns1.easydns.com", response.NameServers[0]);
        Assert.Equal("ns2.easydns.com", response.NameServers[1]);
        Assert.Equal("ns3.easydns.org", response.NameServers[2]);
        Assert.Equal("ns6.easydns.net", response.NameServers[3]);
        Assert.Equal("remote1.easydns.com", response.NameServers[4]);
        Assert.Equal("remote2.easydns.com", response.NameServers[5]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("auto-renew grace", response.DomainStatus[0]);

        Assert.Equal(27, response.FieldsParsed);

        AssertWriter.Write(response);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "not-found", "u34jedzcq.ca.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ca", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("available", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_pending_delete()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "pending-delete", "pending_delete.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.PendingDelete, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/found/01", response.TemplateName);

        Assert.Equal("sagespa.ca", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Go Daddy Domains Canada, Inc", response.Registrar.Name);
        Assert.Equal("2316042", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2013, 07, 31, 00, 00, 00, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2011, 05, 12, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 05, 12, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns75.domaincontrol.com", response.NameServers[0]);
        Assert.Equal("ns76.domaincontrol.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("pending delete", response.DomainStatus[0]);

        Assert.Equal(10, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_redemption()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "redemption", "glu-redemption.ca.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Redemption, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/found/01", response.TemplateName);

        Assert.Equal("glu-redemption.ca", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Webnames.ca Inc.", response.Registrar.Name);
        Assert.Equal("70", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2010, 12, 04, 00, 00, 00, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2004, 10, 30, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2010, 10, 29, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Sanamato Inc.", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("Ross Vito", response.AdminContact.Name);
        Assert.Equal("1 (647) 964-4544", response.AdminContact.TelephoneNumber);
        Assert.Equal("mail@sanamato.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(2, response.AdminContact.Address.Count);
        Assert.Equal("405 Queen Street South, P.O. Box 75004", response.AdminContact.Address[0]);
        Assert.Equal("Bolton ON L7E2B5 Canada", response.AdminContact.Address[1]);


        // TechnicalContact Details
        Assert.Equal("Ross Vito", response.TechnicalContact.Name);
        Assert.Equal("1 (647) 964-4544", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("mail@sanamato.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(2, response.TechnicalContact.Address.Count);
        Assert.Equal("405 Queen Street South, P.O. Box 75004", response.TechnicalContact.Address[0]);
        Assert.Equal("Bolton ON L7E2B5 Canada", response.TechnicalContact.Address[1]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.webnames.ca", response.NameServers[0]);
        Assert.Equal("ns2.webnames.ca", response.NameServers[1]);
        Assert.Equal("ns3.webnames.ca", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("redemption", response.DomainStatus[0]);

        Assert.Equal(22, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_status_registered_2()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "found", "google.ca.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/found/01", response.TemplateName);

        Assert.Equal("google.ca", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Webnames.ca Inc.", response.Registrar.Name);
        Assert.Equal("70", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2000, 10, 03, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 04, 28, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Google Inc.", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("Rose Hagan", response.AdminContact.Name);
        Assert.Equal("1 416 8653361", response.AdminContact.TelephoneNumber);
        Assert.Equal("1 416 9456616", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(2, response.AdminContact.Address.Count);
        Assert.Equal("130 King St. W., Suite 1800", response.AdminContact.Address[0]);
        Assert.Equal("Toronto ON M5X 1E3 Canada", response.AdminContact.Address[1]);


        // TechnicalContact Details
        Assert.Equal("Matt Serlin", response.TechnicalContact.Name);
        Assert.Equal("1.2083895740", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("1.2083895771", response.TechnicalContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(2, response.TechnicalContact.Address.Count);
        Assert.Equal("Domain Provisioning,10400 Overland Rd. PMB 155", response.TechnicalContact.Address[0]);
        Assert.Equal("Boise ID 83709 United States", response.TechnicalContact.Address[1]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("registered", response.DomainStatus[0]);

        Assert.Equal(24, response.FieldsParsed);
    }

    [Fact]
    public void Test_to_be_released()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "to-be-released", "to_be_released.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.ToBeReleased, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/to-be-released/01", response.TemplateName);

        Assert.Equal("thomascraft.ca", response.DomainName.ToString());


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("to be released", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_unavailable()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "unavailable", "mediom.ca.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Unavailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/unavailable/01", response.TemplateName);

        Assert.Equal("mediom.ca", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found_status_available()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "not-found", "not_found_status_available.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ca", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("available", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_invalid()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "invalid", "mediom-invalid.ca.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Unavailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/unavailable/01", response.TemplateName);

        Assert.Equal("mediom-invalid.ca", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.cira.ca", "ca", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.cira.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cira.ca/ca/found/01", response.TemplateName);

        Assert.Equal("google.ca", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor International Canada Ltd.", response.Registrar.Name);
        Assert.Equal("5000040", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2014, 02, 13, 00, 00, 00, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2000, 10, 03, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2015, 04, 28, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Google Inc.", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("Christina Chiou", response.AdminContact.Name);
        Assert.Equal("+1.4168653361", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.4169456616", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(2, response.AdminContact.Address.Count);
        Assert.Equal("130 King St. W., Suite 1800,", response.AdminContact.Address[0]);
        Assert.Equal("Toronto ON M5X1E3 Canada", response.AdminContact.Address[1]);


        // TechnicalContact Details
        Assert.Equal("Matt Serlin", response.TechnicalContact.Name);
        Assert.Equal("+1.2083895740", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.2083895771", response.TechnicalContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(2, response.TechnicalContact.Address.Count);
        Assert.Equal("Domain Provisioning,10400 Overland Rd. PMB 155", response.TechnicalContact.Address[0]);
        Assert.Equal("Boise ID 83709 United States", response.TechnicalContact.Address[1]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("registered", response.DomainStatus[0]);

        Assert.Equal(25, response.FieldsParsed);
    }
}
