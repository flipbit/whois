using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.SaCom
{
    public class SaComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public SaComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "sa.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "sa.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/Found", response.TemplateName);

            Assert.Equal("fynbos.sa.com", response.DomainName.ToString());
            Assert.Equal("CNIC-DO501005", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Paragon Internet Group", response.Registrar.Name);
            Assert.Equal("http://www.paragon.net.uk", response.Registrar.Url);
            Assert.Equal("020 3137 7651", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 11, 2, 13, 42, 11, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2007, 9, 27, 18, 14, 53, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 9, 27, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("H323273", response.Registrant.RegistryId);
            Assert.Equal("Maarten Groos", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("farm 215 fynbos reserve", response.Registrant.Address[0]);
            Assert.Equal("PO Box 1314", response.Registrant.Address[1]);
            Assert.Equal("Gansbaai", response.Registrant.Address[2]);
            Assert.Equal("Western Cape", response.Registrant.Address[3]);
            Assert.Equal("7220", response.Registrant.Address[4]);
            Assert.Equal("ZA", response.Registrant.Address[5]);

            Assert.Equal("+27.283880920", response.Registrant.TelephoneNumber);
            Assert.Equal("maarten@farm215.co.za", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("H323273", response.AdminContact.RegistryId);
            Assert.Equal("Maarten Groos", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("farm 215 fynbos reserve", response.AdminContact.Address[0]);
            Assert.Equal("PO Box 1314", response.AdminContact.Address[1]);
            Assert.Equal("Gansbaai", response.AdminContact.Address[2]);
            Assert.Equal("Western Cape", response.AdminContact.Address[3]);
            Assert.Equal("7220", response.AdminContact.Address[4]);
            Assert.Equal("ZA", response.AdminContact.Address[5]);

            Assert.Equal("+27.283880920", response.AdminContact.TelephoneNumber);
            Assert.Equal("maarten@farm215.co.za", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.Equal("C30342", response.TechnicalContact.RegistryId);
            Assert.Equal("Seb de Lemos", response.TechnicalContact.Name);
            Assert.Equal("Paragon Internet Group", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("St Andrew's House", response.TechnicalContact.Address[0]);
            Assert.Equal("St Mary's Walk", response.TechnicalContact.Address[1]);
            Assert.Equal("Maidenhead", response.TechnicalContact.Address[2]);
            Assert.Equal("Berkshire", response.TechnicalContact.Address[3]);
            Assert.Equal("SL6 1QZ", response.TechnicalContact.Address[4]);
            Assert.Equal("GB", response.TechnicalContact.Address[5]);

            Assert.Equal("+44.2031377651", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("domains@paragon.net.uk", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1191.websitewelcome.com", response.NameServers[0]);
            Assert.Equal("ns1192.websitewelcome.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(44, response.FieldsParsed);
        }
    }
}
