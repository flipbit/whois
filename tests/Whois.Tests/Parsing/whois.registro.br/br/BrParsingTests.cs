using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registro.Br.Br;

public class BrParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public BrParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.registro.br", "br", "found", "hostgator.com.br.txt");
        var response = parser.Parse("whois.registro.br", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registro.br/br/found/01", response.TemplateName);

        Assert.Equal("hostgator.com.br", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2026, 05, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 09, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Equal("15.754.475/0001-40", response.Registrant.RegistryId);
        Assert.Equal("Andr� Carvalho Zica", response.Registrant.Name);


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // BillingContact Details
        Assert.Null(response.BillingContact);


        // TechnicalContact Details
        Assert.Equal("HOBRA", response.TechnicalContact.RegistryId);
        Assert.Equal("Hostgator Brasil", response.TechnicalContact.Name);
        Assert.Equal("registrobr@hostgator.com.br", response.TechnicalContact.Email);
        Assert.Equal(new DateTime(2007, 12, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("jessica.ns.cloudflare.com", response.NameServers[0]);
        Assert.Equal("ray.ns.cloudflare.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("published", response.DomainStatus[0]);

        Assert.Equal(16, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.registro.br", "br", "not-found", "u34jedzcq.br.txt");
        var response = parser.Parse("whois.registro.br", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registro.br/br/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.br", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found_status_available_limited()
    {
        var sample = SampleReader.Read("whois.registro.br", "br", "not-found", "not_found_status_available_limited.txt");
        var response = parser.Parse("whois.registro.br", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registro.br/br/throttled/02", response.TemplateName);

        Assert.Equal("u34jedzcq.br", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.registro.br", "br", "found", "google.com.br.txt");
        var response = parser.Parse("whois.registro.br", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registro.br/br/found/01", response.TemplateName);

        Assert.Equal("google.com.br", response.DomainName.ToString());

        Assert.Equal(new DateTime(2026, 04, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1999, 05, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("06.990.590/0001-23", response.Registrant.RegistryId);
        Assert.Equal("Domain Administrator", response.Registrant.Name);

        // AdminContact Details
        Assert.Null(response.AdminContact);


        // BillingContact Details
        Assert.Null(response.BillingContact);


        // TechnicalContact Details
        Assert.Equal("DOADM17", response.TechnicalContact.RegistryId);
        Assert.Equal("Domain Admin", response.TechnicalContact.Name);
        Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);
        Assert.Equal(new DateTime(2010, 05, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("published", response.DomainStatus[0]);

        Assert.Equal(18, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered_limited()
    {
        var sample = SampleReader.Read("whois.registro.br", "br", "found", "registro.br.txt");
        var response = parser.Parse("whois.registro.br", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registro.br/br/found/01", response.TemplateName);

        Assert.Equal("registro.br", response.DomainName.ToString());

        // Registrant Details
        Assert.Equal("N�cleo de Inf. e Coord. do Ponto BR - NIC.BR", response.Registrant.Name);

        Assert.Equal(14, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_001hosting()
    {
        var sample = SampleReader.Read("whois.registro.br", "br", "found", "001hosting.com.br.txt");
        var response = parser.Parse("whois.registro.br", sample);

        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registro.br/br/found/01", response.TemplateName);

        Assert.Equal("001hosting.com.br", response.DomainName.ToString());

        Assert.Equal(new DateTime(2019, 04, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 09, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("350.562.738-05", response.Registrant.RegistryId);
        Assert.Equal("Ultra Provedor", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("ULPRO5", response.AdminContact.RegistryId);
        Assert.Equal("Ultra Provedor", response.AdminContact.Name);
        Assert.Equal("registro@ultraprovedor.com.br", response.AdminContact.Email);
        Assert.Equal(new DateTime(2018, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);


        // BillingContact Details
        Assert.Equal("ULPRO5", response.BillingContact.RegistryId);
        Assert.Equal("Ultra Provedor", response.BillingContact.Name);
        Assert.Equal("registro@ultraprovedor.com.br", response.BillingContact.Email);
        Assert.Equal(new DateTime(2018, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.BillingContact.Created);


        // TechnicalContact Details
        Assert.Equal("ULPRO5", response.TechnicalContact.RegistryId);
        Assert.Equal("Ultra Provedor", response.TechnicalContact.Name);
        Assert.Equal("registro@ultraprovedor.com.br", response.TechnicalContact.Email);
        Assert.Equal(new DateTime(2018, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.ultraprovedor.com.br", response.NameServers[0]);
        Assert.Equal("ns2.ultraprovedor.com.br", response.NameServers[1]);
        Assert.Equal("ns3.ultraprovedor.com.br", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("published", response.DomainStatus[0]);

        Assert.Equal(18, response.FieldsParsed);
    }
}
