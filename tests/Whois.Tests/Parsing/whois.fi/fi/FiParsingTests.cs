using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Fi.Fi
{
    public class FiParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public FiParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.fi", "fi", "found", "oogle.fi.txt");
            var response = parser.Parse("whois.fi", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.fi/fi/found/01", response.TemplateName);

            Assert.Equal("oogle.fi", response.DomainName.ToString());

            Assert.Equal(new DateTime(2013, 06, 22, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2012, 06, 21, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 06, 21, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Minna", response.Registrant.Name);
            Assert.Equal("NURMI", response.Registrant.Organization);
            Assert.Equal("+358201599789", response.Registrant.TelephoneNumber);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("-", response.Registrant.Address[0]);
            Assert.Equal("Huovitie 3", response.Registrant.Address[1]);
            Assert.Equal("00400", response.Registrant.Address[2]);
            Assert.Equal("HELSINKI", response.Registrant.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("a.ns.netim.net", response.NameServers[0]);
            Assert.Equal("b.ns.netim.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Grace Period", response.DomainStatus[0]);

            Assert.Equal("no", response.DnsSecStatus);
            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.fi", "fi", "not-found", "not_found.txt");
            var response = parser.Parse("whois.fi", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/03", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.fi", "fi", "found", "google.fi.txt");
            var response = parser.Parse("whois.fi", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.fi/fi/found/01", response.TemplateName);

            Assert.Equal("google.fi", response.DomainName.ToString());

            Assert.Equal(new DateTime(2013, 06, 07, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 06, 30, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 07, 04, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Finland Oy", response.Registrant.Name);
            Assert.Equal("09073468", response.Registrant.Organization);
            Assert.Equal("35896966890", response.Registrant.TelephoneNumber);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Domain Administrator", response.Registrant.Address[0]);
            Assert.Equal("Mannerheimintie 12 B", response.Registrant.Address[1]);
            Assert.Equal("00100", response.Registrant.Address[2]);
            Assert.Equal("HELSINKI", response.Registrant.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Granted", response.DomainStatus[0]);

            Assert.Equal("no", response.DnsSecStatus);
            Assert.Equal(18, response.FieldsParsed);
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.fi", "fi", "reserved", "reserved.txt");
            var response = parser.Parse("whois.fi", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.fi/fi/reserved/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }
    }
}
