using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dotname.Co.Kr.Com
{
    public class ComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dotname.co.kr", "com", "found", "found.txt");
            
            var response = parser.Parse("whois.dotname.co.kr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/02", response.TemplateName);

            Assert.Equal("ggemtv.com", response.DomainName.ToString());
            Assert.Equal("2282446647_DOMAIN_COM-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Dotname Korea Corp.", response.Registrar.Name);
            Assert.Equal("1132", response.Registrar.IanaId);
            Assert.Equal("http://www.dotname.co.kr", response.Registrar.Url);
            Assert.Equal("whois.dotname.co.kr", response.Registrar.WhoisServer.Value);
            Assert.Equal("abuse@dotnamekorea.com", response.Registrar.AbuseEmail);
            Assert.Equal("+82.7070900820", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2019, 07, 05, 03, 28, 02, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2018, 07, 05, 01, 48, 01, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2020, 07, 05, 01, 48, 01, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns11.dnstool.net", response.NameServers[0]);
            Assert.Equal("ns12.dnstool.net", response.NameServers[1]);
            Assert.Equal("ns13.dnstool.net", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(17, response.FieldsParsed);
        }
    }
}
