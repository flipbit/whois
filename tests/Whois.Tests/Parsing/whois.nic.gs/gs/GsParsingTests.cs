using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Gs.Gs
{
    public class GsParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public GsParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.gs", "gs", "not_found.txt");
            var response = parser.Parse("whois.nic.gs", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.gs/gs/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.gs", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.gs", "gs", "found.txt");
            var response = parser.Parse("whois.nic.gs", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.gs", response.DomainName.ToString());
            Assert.Equal("4258-CoCCA.gs", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1 (208) 389-5740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2012, 06, 06, 09, 11, 23, 837, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 07, 08, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 07, 08, 12, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("681182-CoCCA", response.Registrant.RegistryId);
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("CA", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(4, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("ok", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[3]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(23, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.gs", "gs", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.gs", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound004", response.TemplateName);

            Assert.Equal("u34jedzcq.gs", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.gs", "gs", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.gs", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.gs", response.DomainName.ToString());
            Assert.Equal("4258-CoCCA.gs", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("whois.nic.gs", response.Registrar.WhoisServer.Value);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 12, 06, 07, 35, 24, 997, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 07, 08, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 07, 08, 12, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("955923-CoCCA", response.Registrant.RegistryId);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(4, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[3]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(19, response.FieldsParsed);
        }
    }
}
