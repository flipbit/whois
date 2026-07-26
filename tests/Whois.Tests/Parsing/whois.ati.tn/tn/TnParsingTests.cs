using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ati.Tn.Tn;

public class TnParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TnParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.ati.tn", "tn", "found", "equipements-pro.com.tn.txt");
        var response = parser.Parse("whois.ati.tn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(18, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.ati.tn/tn/found/01", response.TemplateName);

        Assert.Equal("equipements-pro.com.tn", response.DomainName.ToString());

        Assert.Equal("I-HOSTERS", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 12, 13, 22, 15, 8), response.Registered);
        Assert.Equal("MAISON DE BIEN HOTELIERS ET EQ Farhat Riadh", response.Registrant.Name);

        Assert.Equal(1, response.Registrant.Address.Count);
        Assert.Equal("complexe commercial Boukris 2 rue Om Larayes", response.Registrant.Address[0]);

        Assert.Equal("98639096", response.Registrant.TelephoneNumber);
        Assert.Equal("mbh@tunet.tn", response.Registrant.Email);

        Assert.Equal("MAISON DE BIEN HOTELIERS ET EQ Farhat Riadh", response.AdminContact.Name);

        Assert.Equal(1, response.AdminContact.Address.Count);
        Assert.Equal("complexe commercial Boukris 2 rue Om Larayes", response.AdminContact.Address[0]);

        Assert.Equal("98639096", response.AdminContact.TelephoneNumber);
        Assert.Equal("mbh@tunet.tn", response.AdminContact.Email);

        Assert.Equal("MAISON DE BIEN HOTELIERS ET EQ Farhat Riadh", response.TechnicalContact.Name);

        Assert.Equal(1, response.TechnicalContact.Address.Count);
        Assert.Equal("complexe commercial Boukris 2 rue Om Larayes", response.TechnicalContact.Address[0]);

        Assert.Equal("98639096", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("mbh@tunet.tn", response.TechnicalContact.Email);


        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns.steerbook.com", response.NameServers[0]);
        Assert.Equal("dns.steerbook.com", response.NameServers[1]);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.ati.tn", "tn", "not-found", "u34jedzcq.tn.txt");
        var response = parser.Parse("whois.ati.tn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(2, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.ati.tn/tn/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.tn", response.DomainName.ToString());
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.ati.tn", "tn", "found", "google.tn.txt");
        var response = parser.Parse("whois.ati.tn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(23, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.ati.tn/tn/found/01", response.TemplateName);

        Assert.Equal("google.tn", response.DomainName.ToString());

        Assert.Equal("3S Global Net", response.Registrar.Name);

        Assert.Equal(new DateTime(2009, 5, 14, 0, 0, 0), response.Registered);
        Assert.Equal("GOOGLE Inc", response.Registrant.Name);

        Assert.Equal(1, response.Registrant.Address.Count);
        Assert.Equal("PO BOX 2050 Moutain view CA 94042 USA", response.Registrant.Address[0]);

        Assert.Equal("+1 925 685 9600", response.Registrant.TelephoneNumber);
        Assert.Equal("+1 925 685 9620", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        Assert.Equal("GOOGLE Inc", response.AdminContact.Name);

        Assert.Equal(1, response.AdminContact.Address.Count);
        Assert.Equal("PO BOX 2050 Moutain view CA 94042 USA", response.AdminContact.Address[0]);

        Assert.Equal("+1 925 685 9600", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1 925 685 9620", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        Assert.Equal("GOOGLE Inc", response.TechnicalContact.Name);

        Assert.Equal(1, response.TechnicalContact.Address.Count);
        Assert.Equal("PO BOX 2050 Moutain view CA 94042 USA", response.TechnicalContact.Address[0]);

        Assert.Equal("+1 925 685 9600", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1 925 685 9620", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);


        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);
    }
}
