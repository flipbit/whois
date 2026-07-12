using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Audns.Net.Au.Au
{
    public class AuParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AuParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.audns.net.au", "au", "found", "pinewood.com.au.txt");
            var response = parser.Parse("whois.audns.net.au", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(15, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.audns.net.au/au/found/01", response.TemplateName);

            Assert.Equal("pinewood.com.au", response.DomainName.ToString());

            Assert.Equal("Melbourne IT", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 10, 11, 0, 0, 33), response.Updated);
            Assert.Equal("ACN 120 562 905", response.Registrant.RegistryId);
            Assert.Equal("PINEWOOD PROLAB PTY LTD", response.Registrant.Name);

            Assert.Equal("Z116060879386417", response.AdminContact.RegistryId);
            Assert.Equal("PETER TONOLI", response.AdminContact.Name);

            Assert.Equal("Z116060879386417", response.TechnicalContact.RegistryId);
            Assert.Equal("PETER TONOLI", response.TechnicalContact.Name);


            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.dreamhost.com", response.NameServers[0]);
            Assert.Equal("ns2.dreamhost.com", response.NameServers[1]);
            Assert.Equal("ns3.dreamhost.com", response.NameServers[2]);

            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("serverHold (Expired)", response.DomainStatus[0]);
            Assert.Equal("serverUpdateProhibited (Expired)", response.DomainStatus[1]);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.audns.net.au", "au", "not-found", "not_found.txt");
            var response = parser.Parse("whois.audns.net.au", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(1, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.audns.net.au/au/not-found/01", response.TemplateName);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.audns.net.au", "au", "found", "google.com.au.txt");
            var response = parser.Parse("whois.audns.net.au", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(16, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.audns.net.au/au/found/01", response.TemplateName);

            Assert.Equal("google.com.au", response.DomainName.ToString());


            Assert.Equal(new DateTime(2014, 11, 5, 10, 35, 59), response.Updated);
            Assert.Equal("Google INC", response.Registrant.Name);

            Assert.Equal("MMR-122026", response.AdminContact.RegistryId);
            Assert.Equal("Domain Administrator", response.AdminContact.Name);

            Assert.Equal("MMR-87489", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);


            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(4, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);
            Assert.Equal("serverDeleteProhibited (Protected by .auLOCKDOWN)", response.DomainStatus[2]);
            Assert.Equal("serverUpdateProhibited (Protected by .auLOCKDOWN)", response.DomainStatus[3]);
        }
    }
}
