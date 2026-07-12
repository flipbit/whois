using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Es.Es
{
    public class EsParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public EsParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.es", "es", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.es", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.es/es/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.es", "es", "found", "found.txt");
            var response = parser.Parse("whois.nic.es", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.es/es/found/01", response.TemplateName);

            Assert.Equal("google.es", response.DomainName.ToString());

            Assert.Equal(new DateTime(2013, 10, 10, 07, 00, 02, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2003, 09, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 09, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("GOOGLE INC.", response.Registrant.Name);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.google.com", response.NameServers[0]);
            Assert.Equal("ns1.google.com", response.NameServers[1]);

            Assert.Equal(8, response.FieldsParsed);
        }
    }
}
