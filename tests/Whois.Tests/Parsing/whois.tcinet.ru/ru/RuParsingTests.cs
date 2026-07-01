using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tcinet.Ru.Ru
{
    public class RuParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public RuParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tcinet.ru", "ru", "found.txt");
            var response = parser.Parse("whois.tcinet.ru", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.tcinet.ru/Found", response.TemplateName);

            Assert.Equal("masterhost.ru", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("RD-RU", response.Registrar.Name);

            Assert.Equal(new DateTime(1999, 12, 15, 16, 20, 39, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2021, 12, 31, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal(@"LLC ""MASTERHOST""", response.Registrant.Organization);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns3.masterhost.ru", response.NameServers[0]);
            Assert.Equal("ns4.masterhost.ru", response.NameServers[1]);
            Assert.Equal("ns5.masterhost.ru", response.NameServers[2]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("REGISTERED", response.DomainStatus[0]);
            Assert.Equal("DELEGATED", response.DomainStatus[1]);
            Assert.Equal("UNVERIFIED", response.DomainStatus[2]);

            Assert.Equal(10, response.FieldsParsed);        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tcinet.ru", "ru", "not_found.txt");
            var response = parser.Parse("whois.tcinet.ru", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.tcinet.ru/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.tcinet.ru", "ru", "found_status_registered.txt");
            var response = parser.Parse("whois.tcinet.ru", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.tcinet.ru/Found", response.TemplateName);

            Assert.Equal("google.ru", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("RU-CENTER-RU", response.Registrar.Name);

            Assert.Equal(new DateTime(2004, 03, 03, 21, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2021, 03, 04, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google LLC", response.Registrant.Organization);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com.", response.NameServers[0]);
            Assert.Equal("ns2.google.com.", response.NameServers[1]);
            Assert.Equal("ns3.google.com.", response.NameServers[2]);
            Assert.Equal("ns4.google.com.", response.NameServers[3]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("REGISTERED", response.DomainStatus[0]);
            Assert.Equal("DELEGATED", response.DomainStatus[1]);
            Assert.Equal("VERIFIED", response.DomainStatus[2]);

            Assert.Equal(11, response.FieldsParsed);
        }
    }
}
