using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.CoJp;

public class CoJpParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CoJpParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_pending_delete()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "pending-delete", "pending_delete.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.PendingDelete, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/01", response.TemplateName);

        Assert.Equal("gaylife.co.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2012, 08, 08, 12, 00, 43, 000, DateTimeKind.Utc), response.Updated);

        // Registrant Details
        Assert.Equal("Suspended Domain Name", response.Registrant.Name);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Deleted", response.DomainStatus[0]);

        Assert.Equal(5, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "found", "found.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/01", response.TemplateName);

        Assert.Equal("ahoo.co.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2013, 07, 08, 16, 50, 07, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2013, 03, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("yamazakipan corp.", response.Registrant.Name);

        // AdminContact Details
        Assert.Equal("TY20986JP", response.AdminContact.RegistryId);

        // TechnicalContact Details
        Assert.Equal("TY20986JP", response.TechnicalContact.RegistryId);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Registered", response.DomainStatus[0]);

        Assert.Equal(8, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_amazon_co_jp()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "found", "amazon.co.jp.txt");

        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/01", response.TemplateName);

        Assert.Equal("amazon.co.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2018, 12, 01, 01, 01, 57, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2002, 11, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("Amazon, Inc.", response.Registrant.Name);

        // AdminContact Details
        Assert.Equal("JC076JP", response.AdminContact.RegistryId);

        // TechnicalContact Details
        Assert.Equal("IK4644JP", response.TechnicalContact.RegistryId);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.p31.dynect.net", response.NameServers[0]);
        Assert.Equal("ns2.p31.dynect.net", response.NameServers[1]);
        Assert.Equal("pdns1.ultradns.net", response.NameServers[2]);
        Assert.Equal("pdns6.ultradns.co.uk", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Connected", response.DomainStatus[0]);

        Assert.Equal(12, response.FieldsParsed);
    }
}
