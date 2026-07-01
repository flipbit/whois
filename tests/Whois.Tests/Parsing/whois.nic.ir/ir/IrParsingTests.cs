using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ir.Ir
{
    public class IrParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public IrParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ir", "ir", "not_found.txt");
            var response = parser.Parse("whois.nic.ir", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ir/ir/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.ir", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ir", "ir", "found.txt");
            var response = parser.Parse("whois.nic.ir", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ir/ir/Found", response.TemplateName);

            Assert.Equal("google.ir", response.DomainName.ToString());

            Assert.Equal(new DateTime(2014, 02, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2014, 12, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("go438-irnic", response.Registrant.RegistryId);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1 650 623 4000", response.Registrant.TelephoneNumber);
            Assert.Equal("+1 650 618 8571", response.Registrant.FaxNumber);
            Assert.Equal("support@domainservicesltd.co.uk", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(1, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway, Mountain View, CA, US", response.Registrant.Address[0]);


             // AdminContact Details
            Assert.Equal("do210-irnic", response.AdminContact.RegistryId);
            Assert.Equal("Domain Services Ltd", response.AdminContact.Organization);
            Assert.Equal("+44 87 20229870", response.AdminContact.TelephoneNumber);
            Assert.Equal("+44 87 20229871", response.AdminContact.FaxNumber);
            Assert.Equal("admin@domainservicesltd.co.uk", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("2nd Floor 145-147 St.John Street, London, London, UK", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("do210-irnic", response.TechnicalContact.RegistryId);
            Assert.Equal("Domain Services Ltd", response.TechnicalContact.Organization);
            Assert.Equal("+44 87 20229870", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+44 87 20229871", response.TechnicalContact.FaxNumber);
            Assert.Equal("admin@domainservicesltd.co.uk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("2nd Floor 145-147 St.John Street, London, London, UK", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns3.google.com", response.NameServers[0]);
            Assert.Equal("ns4.google.com", response.NameServers[1]);
            Assert.Equal("ns1.google.com", response.NameServers[2]);
            Assert.Equal("ns2.google.com", response.NameServers[3]);

            Assert.Equal(23, response.FieldsParsed);
        }
    }
}
