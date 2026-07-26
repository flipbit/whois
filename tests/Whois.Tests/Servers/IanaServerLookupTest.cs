using Whois.Net;
using Xunit;

namespace Whois.Servers;

public class IanaServerLookupTest
{
    private readonly IanaServerLookup lookup;
    private readonly SampleReader reader;

    public IanaServerLookupTest()
    {
        lookup = new IanaServerLookup();
        reader = new SampleReader();
    }

    [Fact]
    public async System.Threading.Tasks.Task TestLookupCom()
    {
        lookup.TcpReader = new FakeTcpReader(reader.Read("whois.iana.org", "tld", "found", "com.txt"));

        var response = await lookup.Lookup(new WhoisRequest("test.com"));

        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("com", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("whois.verisign-grs.com", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2012, 02, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1985, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("VeriSign Global Registry Services", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("12061 Bluemont Way", response.Registrant.Address[0]);
        Assert.Equal("Reston Virginia 20190", response.Registrant.Address[1]);
        Assert.Equal("United States", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Registry Customer Service", response.AdminContact.Name);
        Assert.Equal("VeriSign Global Registry Services", response.AdminContact.Organization);
        Assert.Equal("+1 703 925-6999", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1 703 948 3978", response.AdminContact.FaxNumber);
        Assert.Equal("info@verisign-grs.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("12061 Bluemont Way", response.AdminContact.Address[0]);
        Assert.Equal("Reston Virginia 20190", response.AdminContact.Address[1]);
        Assert.Equal("United States", response.AdminContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("Registry Customer Service", response.TechnicalContact.Name);
        Assert.Equal("VeriSign Global Registry Services", response.TechnicalContact.Organization);
        Assert.Equal("+1 703 925-6999", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1 703 948 3978", response.TechnicalContact.FaxNumber);
        Assert.Equal("info@verisign-grs.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("12061 Bluemont Way", response.TechnicalContact.Address[0]);
        Assert.Equal("Reston Virginia 20190", response.TechnicalContact.Address[1]);
        Assert.Equal("United States", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(13, response.NameServers.Count);
        Assert.Equal("a.gtld-servers.net", response.NameServers[0]);
        Assert.Equal("b.gtld-servers.net", response.NameServers[1]);
        Assert.Equal("c.gtld-servers.net", response.NameServers[2]);
        Assert.Equal("d.gtld-servers.net", response.NameServers[3]);
        Assert.Equal("e.gtld-servers.net", response.NameServers[4]);
        Assert.Equal("f.gtld-servers.net", response.NameServers[5]);
        Assert.Equal("g.gtld-servers.net", response.NameServers[6]);
        Assert.Equal("h.gtld-servers.net", response.NameServers[7]);
        Assert.Equal("i.gtld-servers.net", response.NameServers[8]);
        Assert.Equal("j.gtld-servers.net", response.NameServers[9]);
        Assert.Equal("k.gtld-servers.net", response.NameServers[10]);
        Assert.Equal("l.gtld-servers.net", response.NameServers[11]);
        Assert.Equal("m.gtld-servers.net", response.NameServers[12]);

        // Domain Status
        Assert.Single(response.DomainStatus);
        Assert.Equal("ACTIVE", response.DomainStatus[0]);

        Assert.Equal(0, response.FieldsParsed);
    }

    [Fact]
    public async System.Threading.Tasks.Task TestLookupBe()
    {
        lookup.TcpReader = new FakeTcpReader(reader.Read("whois.iana.org", "tld", "found", "be.txt"));

        var response = await lookup.Lookup(new WhoisRequest("test.be"));

        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("be", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("whois.dns.be", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2014, 07, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1988, 08, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("DNS Belgium vzw/asbl", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Ubicenter, Philipssite 5, bus 13", response.Registrant.Address[0]);
        Assert.Equal("Leuven  3001", response.Registrant.Address[1]);
        Assert.Equal("Belgium", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Philip Du Bois", response.AdminContact.Name);
        Assert.Equal("DNS Belgium vzw/asbl", response.AdminContact.Organization);
        Assert.Equal("+32 16 28 49 70", response.AdminContact.TelephoneNumber);
        Assert.Equal("+32 16 28 49 71", response.AdminContact.FaxNumber);
        Assert.Equal("legal@dnsbelgium.be", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Ubicenter, Philipssite 5, bus 13", response.AdminContact.Address[0]);
        Assert.Equal("Leuven  3001", response.AdminContact.Address[1]);
        Assert.Equal("Belgium", response.AdminContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("David Goelen", response.TechnicalContact.Name);
        Assert.Equal("DNS Belgium vzw/asbl", response.TechnicalContact.Organization);
        Assert.Equal("+32 16 28 49 70", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+32 16 28 49 71", response.TechnicalContact.FaxNumber);
        Assert.Equal("tech@dnsbelgium.be", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Ubicenter, Philipssite 5, bus 13", response.TechnicalContact.Address[0]);
        Assert.Equal("Leuven  3001", response.TechnicalContact.Address[1]);
        Assert.Equal("Belgium", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("a.ns.dns.be", response.NameServers[0]);
        Assert.Equal("b.ns.dns.be", response.NameServers[1]);
        Assert.Equal("c.ns.dns.be", response.NameServers[2]);
        Assert.Equal("d.ns.dns.be", response.NameServers[3]);
        Assert.Equal("x.ns.dns.be", response.NameServers[4]);
        Assert.Equal("y.ns.dns.be", response.NameServers[5]);

        // Domain Status
        Assert.Single(response.DomainStatus);
        Assert.Equal("ACTIVE", response.DomainStatus[0]);

        Assert.Equal(0, response.FieldsParsed);
    }

    [Fact]
    public async System.Threading.Tasks.Task TestLookupNotFound()
    {
        lookup.TcpReader = new FakeTcpReader(reader.Read("whois.iana.org", "tld", "not-assigned", "not_assigned.txt"));

        var response = await lookup.Lookup(new WhoisRequest("test.be"));

        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("eh", response.DomainName.ToString());


        Assert.Equal(0, response.FieldsParsed);
    }
}
