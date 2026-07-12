using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dot.Tk.Tk
{
    public class TkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public TkParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dot.tk", "tk", "not-found", "not_found.txt");
            var response = parser.Parse("whois.dot.tk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dot.tk/tk/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dot.tk", "tk", "found", "found.txt");
            var response = parser.Parse("whois.dot.tk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dot.tk/tk/found/01", response.TemplateName);

            Assert.Equal("google.tk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2001, 12, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2012, 03, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("eMarkmonitor Inc", response.Registrant.Organization);
            Assert.Equal("+1 208-3895740", response.Registrant.TelephoneNumber);
            Assert.Equal("+1 208-3895799", response.Registrant.FaxNumber);
            Assert.Equal("ccopsbilling@markmonitor.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Ccops Center", response.Registrant.Address[0]);
            Assert.Equal("PMB 155, 10400 Overland Road", response.Registrant.Address[1]);
            Assert.Equal("83709  Boise", response.Registrant.Address[2]);
            Assert.Equal("Idaho", response.Registrant.Address[3]);
            Assert.Equal("U.S.A.", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(17, response.FieldsParsed);
        }
    }
}
