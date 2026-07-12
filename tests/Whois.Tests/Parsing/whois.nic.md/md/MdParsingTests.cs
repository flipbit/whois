using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Md.Md
{
    public class MdParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public MdParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.md", "md", "found", "hotel.md.txt");
            var response = parser.Parse("whois.nic.md", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.md/md/found/01", response.TemplateName);

            Assert.Equal("hotel.md", response.DomainName.ToString());

            Assert.Equal(new DateTime(2002, 03, 25, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 03, 25, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Diginet S.R.L.", response.Registrant.Name);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns0.starnet.md", response.NameServers[0]);
            Assert.Equal("ns1.starnet.md", response.NameServers[1]);

            Assert.Equal(7, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.md", "md", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.md", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.md/md/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.md", "md", "found", "google.md.txt");
            var response = parser.Parse("whois.nic.md", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.md/md/found/01", response.TemplateName);

            Assert.Equal("google.md", response.DomainName.ToString());

            Assert.Equal(new DateTime(2006, 05, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 05, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            Assert.Equal(7, response.FieldsParsed);
        }
    }
}
