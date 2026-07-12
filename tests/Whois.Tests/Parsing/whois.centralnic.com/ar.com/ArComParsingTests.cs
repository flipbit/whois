using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.ArCom
{
    public class ArComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ArComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "ar.com", "not-found", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "ar.com", "found", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

            Assert.Equal("hotel.ar.com", response.DomainName.ToString());
            Assert.Equal("CNIC-DO557730", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("CentralNic Ltd", response.Registrar.Name);
            Assert.Equal("+44.8700170900", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 4, 26, 0, 15, 40, DateTimeKind.Utc), response.Updated!.Value.ToUniversalTime());
            Assert.Equal(new DateTime(2008, 4, 25, 16, 22, 13, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 4, 25, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("H1323241", response.Registrant.RegistryId);
            Assert.Equal("Reserved Domains", response.Registrant.Name);
            Assert.Equal("CentralNic Ltd", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("35-39 Moorgate", response.Registrant.Address[0]);
            Assert.Equal("London", response.Registrant.Address[1]);
            Assert.Equal("EC2R 6AR", response.Registrant.Address[2]);
            Assert.Equal("GB", response.Registrant.Address[3]);

            Assert.Equal("+44.8700170900", response.Registrant.TelephoneNumber);
            Assert.Equal("domains@centralnic.com", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("H1323241", response.AdminContact.RegistryId);
            Assert.Equal("Reserved Domains", response.AdminContact.Name);
            Assert.Equal("CentralNic Ltd", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("35-39 Moorgate", response.AdminContact.Address[0]);
            Assert.Equal("London", response.AdminContact.Address[1]);
            Assert.Equal("EC2R 6AR", response.AdminContact.Address[2]);
            Assert.Equal("GB", response.AdminContact.Address[3]);

            Assert.Equal("+44.8700170900", response.AdminContact.TelephoneNumber);
            Assert.Equal("domains@centralnic.com", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.Equal("H1323241", response.TechnicalContact.RegistryId);
            Assert.Equal("Reserved Domains", response.TechnicalContact.Name);
            Assert.Equal("CentralNic Ltd", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("35-39 Moorgate", response.TechnicalContact.Address[0]);
            Assert.Equal("London", response.TechnicalContact.Address[1]);
            Assert.Equal("EC2R 6AR", response.TechnicalContact.Address[2]);
            Assert.Equal("GB", response.TechnicalContact.Address[3]);

            Assert.Equal("+44.8700170900", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("domains@centralnic.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(6, response.NameServers.Count);
            Assert.Equal("ns0.centralnic-dns.com", response.NameServers[0]);
            Assert.Equal("ns1.centralnic-dns.com", response.NameServers[1]);
            Assert.Equal("ns2.centralnic-dns.com", response.NameServers[2]);
            Assert.Equal("ns3.centralnic-dns.com", response.NameServers[3]);
            Assert.Equal("ns4.centralnic-dns.com", response.NameServers[4]);
            Assert.Equal("ns5.centralnic-dns.com", response.NameServers[5]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(43, response.FieldsParsed);
        }
    }
}
