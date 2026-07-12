using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registro.Br.Br
{
    public class BrParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public BrParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found", "hostgator.com.br.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registro.br/br/found/01", response.TemplateName);

            Assert.Equal("hostgator.com.br", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("HOSTGATOR-BRASIL (43)", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 05, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2005, 09, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2018, 09, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("008.852.780/0001-00", response.Registrant.RegistryId);
            Assert.Equal("Robledo Ribeiro Aloisio", response.Registrant.Name);


             // AdminContact Details
            Assert.Equal("HOBRA", response.AdminContact.RegistryId);
            Assert.Equal("Hostgator Brasil", response.AdminContact.Name);
            Assert.Equal("rob@hostgator.com.br", response.AdminContact.Email);
            Assert.Equal(new DateTime(2007, 12, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);


             // BillingContact Details
            Assert.Equal("HOBRA", response.BillingContact.RegistryId);
            Assert.Equal("Hostgator Brasil", response.BillingContact.Name);
            Assert.Equal("rob@hostgator.com.br", response.BillingContact.Email);
            Assert.Equal(new DateTime(2007, 12, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.BillingContact.Created);


             // TechnicalContact Details
            Assert.Equal("HOBRA", response.TechnicalContact.RegistryId);
            Assert.Equal("Hostgator Brasil", response.TechnicalContact.Name);
            Assert.Equal("rob@hostgator.com.br", response.TechnicalContact.Email);
            Assert.Equal(new DateTime(2007, 12, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.hostgator.com.br", response.NameServers[0]);
            Assert.Equal("ns2.hostgator.com.br", response.NameServers[1]);
            Assert.Equal("ns3.hostgator.com.br", response.NameServers[2]);
            Assert.Equal("ns4.hostgator.com.br", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("published", response.DomainStatus[0]);

            Assert.Equal(22, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "not-found", "u34jedzcq.br.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

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
            Assert.Equal(WhoisStatus.Throttled, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registro.br/br/throttled/02", response.TemplateName);

            Assert.Equal("u34jedzcq.br", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found", "google.com.br.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registro.br/br/found/01", response.TemplateName);

            Assert.Equal("google.com.br", response.DomainName.ToString());

            Assert.Equal(new DateTime(2017, 04, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 05, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("06.990.590/0001-23", response.Registrant.RegistryId);
            Assert.Equal("Domain Administrator", response.Registrant.Name);

             // AdminContact Details
            Assert.Equal("DOADM17", response.AdminContact.RegistryId);
            Assert.Equal("Domain Admin", response.AdminContact.Name);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);
            Assert.Equal(new DateTime(2010, 05, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);


             // BillingContact Details
            Assert.Equal("NAB51", response.BillingContact.RegistryId);


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

            Assert.Equal(20, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found_status_registered_limited()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found", "registro.br.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Throttled, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registro.br/br/throttled/01", response.TemplateName);

            Assert.Equal("registro.br", response.DomainName.ToString());

             // Registrant Details
            Assert.Equal("Núcleo de Informação e Coordenação do Ponto BR (662379)", response.Registrant.Name);

            Assert.Equal(3, response.FieldsParsed);
        }
        
        [Fact]
        public void Test_found_001hosting()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found", "001hosting.com.br.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
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
}
