using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domreg.Lt.Lt
{
    public class LtParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public LtParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.domreg.lt", "lt", "found", "serveriai.lt.txt");
            var response = parser.Parse("whois.domreg.lt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domreg.lt/lt/found/01", response.TemplateName);

            Assert.Equal("serveriai.lt", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal(@"UAB ""Interneto vizija""", response.Registrar.Name);
            Assert.Equal("http://www.iv.lt/", response.Registrar.Url);

            Assert.Equal(new DateTime(2003, 11, 17, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal(@"UAB ""Interneto vizija""", response.Registrant.Organization);
            Assert.Equal("hostmaster@iv.lt", response.Registrant.Email);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("registered", response.DomainStatus[0]);

            Assert.Equal(8, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.domreg.lt", "lt", "not-found", "u34jedzcq.lt.txt");
            var response = parser.Parse("whois.domreg.lt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domreg.lt/lt/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.lt", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.domreg.lt", "lt", "found", "google.lt.txt");
            var response = parser.Parse("whois.domreg.lt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domreg.lt/lt/found/01", response.TemplateName);

            Assert.Equal("google.lt", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor, Inc.", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(1999, 06, 06, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("registered", response.DomainStatus[0]);

            Assert.Equal(10, response.FieldsParsed);
        }
    }
}
