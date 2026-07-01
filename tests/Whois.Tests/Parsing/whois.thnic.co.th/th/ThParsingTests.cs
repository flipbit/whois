using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Thnic.Co.Th.Th
{
    public class ThParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ThParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.thnic.co.th", "th", "not_found.txt");
            var response = parser.Parse("whois.thnic.co.th", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.thnic.co.th/th/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.co.th", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.thnic.co.th", "th", "found.txt");
            var response = parser.Parse("whois.thnic.co.th", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.thnic.co.th/th/Found", response.TemplateName);

            Assert.Equal("google.co.th", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("T.H.NIC Co., Ltd.", response.Registrar.Name);

            Assert.Equal(new DateTime(2012, 09, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 10, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 10, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("2400 Bayshore Parkway, Mountain Veiw, CA", response.Registrant.Address[0]);
            Assert.Equal("94043", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // TechnicalContact Details
            Assert.Equal("13244", response.TechnicalContact.RegistryId);
            Assert.Equal("MarkMonitor Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("391 N Ancestor Place, Boise, ID", response.TechnicalContact.Address[0]);
            Assert.Equal("83704", response.TechnicalContact.Address[1]);
            Assert.Equal("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(20, response.FieldsParsed);
        }
    }
}
