using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Lc
{
    public class LcParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public LcParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "lc", "not-found", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(1, response.FieldsParsed);
            Assert.Equal("generic/tld/not-found/01", response.TemplateName);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "lc", "found", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("nic.lc", response.DomainName.ToString());
            Assert.Equal("D946482-LRCC", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("NicLc Registrar (R144-LRCC)", response.Registrar.Name);

            Assert.Equal(new DateTime(2008, 12, 08, 19, 25, 09, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2002, 12, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2009, 12, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("LC-54921", response.Registrant.RegistryId);
            Assert.Equal("Nic LC Admin", response.Registrant.Name);
            Assert.Equal("Nic LC", response.Registrant.Organization);
            Assert.Equal("+758.4520220", response.Registrant.TelephoneNumber);
            Assert.Equal("nic@nic.lc", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("#4 Colony House", response.Registrant.Address[0]);
            Assert.Equal("John Compton Hwy", response.Registrant.Address[1]);
            Assert.Equal("Castries", response.Registrant.Address[2]);
            Assert.Equal("Not Provided", response.Registrant.Address[3]);
            Assert.Equal("Not Provided", response.Registrant.Address[4]);
            Assert.Equal("LC", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.Equal("LC-51893", response.AdminContact.RegistryId);
            Assert.Equal("Nic LC Hostmaster", response.AdminContact.Name);
            Assert.Equal("Nic LC", response.AdminContact.Organization);
            Assert.Equal("+758.4520220", response.AdminContact.TelephoneNumber);
            Assert.Equal("hostmaster@nic.lc", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("#4 Colony House", response.AdminContact.Address[0]);
            Assert.Equal("Not Provided", response.AdminContact.Address[1]);
            Assert.Equal("Castries", response.AdminContact.Address[2]);
            Assert.Equal("Not Provided", response.AdminContact.Address[3]);
            Assert.Equal("Not Provided", response.AdminContact.Address[4]);
            Assert.Equal("LC", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("LC-53407", response.TechnicalContact.RegistryId);
            Assert.Equal("Nic LC Technical", response.TechnicalContact.Name);
            Assert.Equal("Nic LC", response.TechnicalContact.Organization);
            Assert.Equal("+758.4520220", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("technical@nic.lc", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("#4 Colony House", response.TechnicalContact.Address[0]);
            Assert.Equal("Not Provided", response.TechnicalContact.Address[1]);
            Assert.Equal("Castries", response.TechnicalContact.Address[2]);
            Assert.Equal("Not Provided", response.TechnicalContact.Address[3]);
            Assert.Equal("Not Provided", response.TechnicalContact.Address[4]);
            Assert.Equal("LC", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.nic.ag", response.NameServers[0]);
            Assert.Equal("ns.patricklay.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("OK", response.DomainStatus[0]);

            Assert.Equal(43, response.FieldsParsed);
        }
    }
}
