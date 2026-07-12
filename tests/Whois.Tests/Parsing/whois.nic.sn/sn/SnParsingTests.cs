using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sn.Sn
{
    public class SnParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public SnParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.sn", "sn", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.sn", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            AssertWriter.Write(response);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.sn", "sn", "found", "found.txt");
            var response = parser.Parse("whois.nic.sn", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.sn/sn/found/01", response.TemplateName);

            Assert.Equal("google.sn", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("registry", response.Registrar.Name);

            Assert.Equal(new DateTime(2008, 05, 08, 17, 59, 38, 430, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("C4-SN", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.Equal("C5-SN", response.AdminContact.RegistryId);


             // TechnicalContact Details
            Assert.Equal("C6-SN", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(11, response.FieldsParsed);
        }
    }
}
