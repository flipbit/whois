using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Pnina.Ps.Ps
{
    public class PsParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public PsParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.pnina.ps", "ps", "not-found", "u34jedzcq.ps.txt");
            var response = parser.Parse("whois.pnina.ps", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/05", response.TemplateName);

            Assert.Equal("u34jedzcq.ps", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.pnina.ps", "ps", "found", "google.ps.txt");
            var response = parser.Parse("whois.pnina.ps", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.ps", response.DomainName.ToString());
            Assert.Equal("21665-PS", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("+1-208-389-5740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2004, 05, 18, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 05, 18, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("21544-PS", response.Registrant.RegistryId);
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("001-6-503300100", response.Registrant.TelephoneNumber);
            Assert.Equal("001-6-506188571", response.Registrant.FaxNumber);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy Mountain View- CA- US 94043", response.Registrant.Address[0]);
            Assert.Equal("CA", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("21466-PS", response.AdminContact.RegistryId);
            Assert.Equal("markmonitor-Inc", response.AdminContact.Name);
            Assert.Equal("001-2-083895740", response.AdminContact.TelephoneNumber);
            Assert.Equal("001-2-083895771", response.AdminContact.FaxNumber);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("10400 Overland Rd- PMB 155- Boise-ID-US 83709-1433", response.AdminContact.Address[0]);
            Assert.Equal("Boise", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.Equal("21544-PS", response.BillingContact.RegistryId);
            Assert.Equal("Google Inc.", response.BillingContact.Name);
            Assert.Equal("001-6-503300100", response.BillingContact.TelephoneNumber);
            Assert.Equal("001-6-506188571", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.Equal(3, response.BillingContact.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy Mountain View- CA- US 94043", response.BillingContact.Address[0]);
            Assert.Equal("CA", response.BillingContact.Address[1]);
            Assert.Equal("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("21466-PS", response.TechnicalContact.RegistryId);
            Assert.Equal("markmonitor-Inc", response.TechnicalContact.Name);
            Assert.Equal("001-2-083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("001-2-083895771", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("10400 Overland Rd- PMB 155- Boise-ID-US 83709-1433", response.TechnicalContact.Address[0]);
            Assert.Equal("Boise", response.TechnicalContact.Address[1]);
            Assert.Equal("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);

            // Domain Status
            Assert.Equal(5, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);
            Assert.Equal("ok", response.DomainStatus[2]);
            Assert.Equal("clientRenewProhibited", response.DomainStatus[3]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[4]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(44, response.FieldsParsed);
        }
    }
}
