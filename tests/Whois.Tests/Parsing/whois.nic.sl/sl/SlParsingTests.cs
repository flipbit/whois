using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sl.Sl
{
    public class SlParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public SlParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.sl", "sl", "not_found.txt");
            var response = parser.Parse("whois.nic.sl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.sl/sl/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.sl", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.sl", "sl", "found.txt");
            var response = parser.Parse("whois.nic.sl", sample);

            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.sl/sl/Found", response.TemplateName);

            Assert.Equal("google.sl", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("NIC.SL (http://www.nic.sl)", response.Registrar.Name);

            Assert.Equal(new DateTime(2008, 05, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 05, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("C15964-1211155136", response.Registrant.RegistryId);
            Assert.Equal("Domain Admin", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("1-6502530000", response.Registrant.TelephoneNumber);
            Assert.Equal("1-6506188571", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("Ca", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("Us", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("C15964-1211155137", response.AdminContact.RegistryId);
            Assert.Equal("Ccops Domains", response.AdminContact.Name);
            Assert.Equal("Markmonitor Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.2083895740", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.AdminContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("10400 Overland Road Pmb 155", response.AdminContact.Address[0]);
            Assert.Equal("Boise", response.AdminContact.Address[1]);
            Assert.Equal("Id", response.AdminContact.Address[2]);
            Assert.Equal("83709", response.AdminContact.Address[3]);
            Assert.Equal("Us", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("C15964-1211155138", response.TechnicalContact.RegistryId);
            Assert.Equal("Domain Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
            Assert.Equal("Ca", response.TechnicalContact.Address[2]);
            Assert.Equal("94043", response.TechnicalContact.Address[3]);
            Assert.Equal("Us", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(42, response.FieldsParsed);
        }
    }
}
