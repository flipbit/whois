using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.Jp;

public class JpParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public JpParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_suspended()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "jp", "suspended", "suspended.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Suspended, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/02", response.TemplateName);

        Assert.Equal("veganwiz.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2012, 08, 01, 00, 29, 53, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 07, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 08, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Suspended", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_to_be_suspended()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "jp", "found", "other_status_to_be_suspended.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Suspended, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/02", response.TemplateName);

        Assert.Equal("flirtbox.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 12, 21, 18, 30, 48, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 12, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Tobias Marx", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("Tobias Marx", response.AdminContact.Name);
        Assert.Equal("+4915122947636", response.AdminContact.TelephoneNumber);
        Assert.Equal("superoverdrive@gmx.de", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(2, response.AdminContact.Address.Count);
        Assert.Equal("166-0002", response.AdminContact.Address[0]);
        Assert.Equal("3-43-13 Kouenji-kita Suginami-ku", response.AdminContact.Address[1]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.hans.hosteurope.de", response.NameServers[0]);
        Assert.Equal("ns2.hans.hosteurope.de", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("To be suspended", response.DomainStatus[0]);

        Assert.Equal(14, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "jp", "found", "found.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/02", response.TemplateName);

        Assert.Equal("fashionwatch.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 10, 18, 11, 30, 47, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 05, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 05, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("coco coco", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("coco coco", response.AdminContact.Name);
        Assert.Equal("1312748435", response.AdminContact.TelephoneNumber);
        Assert.Equal("wld19800720@163.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("166-0002", response.AdminContact.Address[0]);
        Assert.Equal("3-43-13 Koenji-kita", response.AdminContact.Address[1]);
        Assert.Equal("Suginami-ku", response.AdminContact.Address[2]);
        Assert.Equal("Tokyo", response.AdminContact.Address[3]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns172.ip-asia.com", response.NameServers[0]);
        Assert.Equal("ns171.ip-asia.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(16, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "jp", "not-found", "not_found.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "jp", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/02", response.TemplateName);

        Assert.Equal("google.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2013, 06, 01, 01, 05, 07, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 05, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 05, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Google Inc.", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("Google Inc.", response.AdminContact.Name);
        Assert.Equal("16502530000", response.AdminContact.TelephoneNumber);
        Assert.Equal("16502530001", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("94043", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[2]);
        Assert.Equal("US", response.AdminContact.Address[3]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(19, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "jp", "reserved", "reserved.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/02", response.TemplateName);

        Assert.Equal("example.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2001, 02, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Reserved", response.DomainStatus[0]);

        Assert.Equal(4, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_ameblo_jp()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "jp", "found", "ameblo.jp.txt");

        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/02", response.TemplateName);

        Assert.Equal("ameblo.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2018, 08, 01, 01, 05, 09, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2004, 07, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2019, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("CyberAgent, Inc.", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("CyberAgent, Inc.", response.AdminContact.Name);
        Assert.Equal("03-5459-6150", response.AdminContact.TelephoneNumber);
        Assert.Equal("03-5784-7070", response.AdminContact.FaxNumber);
        Assert.Equal("dns-ssl-info@cyberagent.co.jp", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("150-0044", response.AdminContact.Address[0]);
        Assert.Equal("Shibuya-ku", response.AdminContact.Address[1]);
        Assert.Equal("19-1 Maruyamacho", response.AdminContact.Address[2]);
        Assert.Equal("Shibuya Prime Plaza 2F", response.AdminContact.Address[3]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("a1-5.akam.net", response.NameServers[0]);
        Assert.Equal("a11-66.akam.net", response.NameServers[1]);
        Assert.Equal("a20-67.akam.net", response.NameServers[2]);
        Assert.Equal("a4-64.akam.net", response.NameServers[3]);
        Assert.Equal("a6-65.akam.net", response.NameServers[4]);
        Assert.Equal("a7-66.akam.net", response.NameServers[5]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(21, response.FieldsParsed);
    }
}
