using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Durban.Whois.Registry.Net.Za.Durban
{
    public class DurbanParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public DurbanParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("durban-whois.registry.net.za", "durban", "not-found", "not_found.txt");
            var response = parser.Parse("durban-whois.registry.net.za", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(2, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);

            Assert.Equal("nosuchdomain.durban", response.DomainName.ToString());
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("durban-whois.registry.net.za", "durban", "found", "found.txt");
            var response = parser.Parse("durban-whois.registry.net.za", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("durban-whois.registry.net.za/durban/found/01", response.TemplateName);

            Assert.Equal("wordpress.durban", response.DomainName.ToString());
            Assert.Equal("dom_7G-9999", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("durban-whois1.registry.net.za", response.Registrar.WhoisServer.Value);

            Assert.Equal(new DateTime(2014, 11, 11, 6, 0, 3), response.Updated);
            Assert.Equal(new DateTime(2014, 11, 4, 6, 0, 1), response.Registered);
            Assert.Equal(new DateTime(2016, 11, 4, 6, 0, 1), response.Expiration);

             // Registrant Details
            Assert.Equal("mmr-132163", response.Registrant.RegistryId);
            Assert.Equal("DNStination Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("425 Market St 5th Floor", response.Registrant.Address[0]);
            Assert.Equal("San Francisco", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94105", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);

            Assert.Equal("+1.4155319335", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.4155319336", response.Registrant.FaxNumber);
            Assert.Equal("admin@dnstinations.com", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("mmr-132163", response.AdminContact.RegistryId);
            Assert.Equal("DNStination Inc.", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("425 Market St 5th Floor", response.AdminContact.Address[0]);
            Assert.Equal("San Francisco", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94105", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);

            Assert.Equal("+1.4155319335", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.4155319336", response.AdminContact.FaxNumber);
            Assert.Equal("admin@dnstinations.com", response.AdminContact.Email);


             // BillingContact Details
            Assert.Equal("mmr-132163", response.BillingContact.RegistryId);
            Assert.Equal("DNStination Inc.", response.BillingContact.Name);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("425 Market St 5th Floor", response.BillingContact.Address[0]);
            Assert.Equal("San Francisco", response.BillingContact.Address[1]);
            Assert.Equal("CA", response.BillingContact.Address[2]);
            Assert.Equal("94105", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);

            Assert.Equal("+1.4155319335", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.4155319336", response.BillingContact.FaxNumber);
            Assert.Equal("admin@dnstinations.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("mmr-132163", response.TechnicalContact.RegistryId);
            Assert.Equal("DNStination Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("425 Market St 5th Floor", response.TechnicalContact.Address[0]);
            Assert.Equal("San Francisco", response.TechnicalContact.Address[1]);
            Assert.Equal("CA", response.TechnicalContact.Address[2]);
            Assert.Equal("94105", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);

            Assert.Equal("+1.4155319335", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.4155319336", response.TechnicalContact.FaxNumber);
            Assert.Equal("admin@dnstinations.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns3.markmonitor.com", response.NameServers[0]);
            Assert.Equal("ns1.markmonitor.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);

            Assert.Equal(52, response.FieldsParsed);
        }
    }
}
