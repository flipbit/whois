using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Website.Ws.Ws
{
    public class WsParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public WsParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.website.ws", "ws", "not_found.txt");
            var response = parser.Parse("whois.website.ws", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.website.ws/ws/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.ws", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.website.ws", "ws", "found.txt");
            var response = parser.Parse("whois.website.ws", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.website.ws/ws/Found", response.TemplateName);

            Assert.Equal("google.ws", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal(".WS Registry", response.Registrar.Name);
            Assert.Equal("whois.website.ws", response.Registrar.WhoisServer.Value);
            Assert.Equal("support@website.ws", response.Registrar.AbuseEmail);

            Assert.Equal(new DateTime(2008, 12, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2002, 03, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 03, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google, Inc.", response.Registrant.Name);


             // AdminContact Details
            Assert.Equal("6503300100", response.AdminContact.TelephoneNumber);
            Assert.Equal("kulpreet@google.com", response.AdminContact.Email);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(15, response.FieldsParsed);
        }
    }
}
