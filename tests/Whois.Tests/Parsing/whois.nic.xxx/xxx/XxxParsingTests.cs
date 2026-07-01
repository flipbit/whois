using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Xxx.Xxx
{
    public class XxxParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public XxxParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.xxx", "xxx", "not_found.txt");
            var response = parser.Parse("whois.nic.xxx", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound001", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.xxx", "xxx", "found.txt");
            var response = parser.Parse("whois.nic.xxx", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("masala.xxx", response.DomainName.ToString());
            Assert.Equal("D130773-XXX", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Mesh Digital Limited (R3228-XXX)", response.Registrar.Name);
            Assert.Equal("1390", response.Registrar.IanaId);

            Assert.Equal(new DateTime(2013, 12, 02, 22, 20, 04, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 12, 01, 01, 37, 55, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 12, 01, 01, 37, 55, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("MNT5BB23000590", response.Registrant.RegistryId);
            Assert.Equal("Domainmonster.com Privacy Service", response.Registrant.Name);
            Assert.Equal("Identity Protect Limited", response.Registrant.Organization);
            Assert.Equal("+44.1483307527", response.Registrant.TelephoneNumber);
            Assert.Equal("+44.1483304031", response.Registrant.FaxNumber);
            Assert.Equal("masala.xxx@privatemonster.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("PO Box 795", response.Registrant.Address[0]);
            Assert.Equal("Godalming", response.Registrant.Address[1]);
            Assert.Equal("Surrey", response.Registrant.Address[2]);
            Assert.Equal("GU7 9GA", response.Registrant.Address[3]);
            Assert.Equal("GB", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("MNT5BB23000590", response.AdminContact.RegistryId);
            Assert.Equal("Domainmonster.com Privacy Service", response.AdminContact.Name);
            Assert.Equal("Identity Protect Limited", response.AdminContact.Organization);
            Assert.Equal("+44.1483307527", response.AdminContact.TelephoneNumber);
            Assert.Equal("+44.1483304031", response.AdminContact.FaxNumber);
            Assert.Equal("masala.xxx@privatemonster.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("PO Box 795", response.AdminContact.Address[0]);
            Assert.Equal("Godalming", response.AdminContact.Address[1]);
            Assert.Equal("Surrey", response.AdminContact.Address[2]);
            Assert.Equal("GU7 9GA", response.AdminContact.Address[3]);
            Assert.Equal("GB", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("MNT5BB23000590", response.TechnicalContact.RegistryId);
            Assert.Equal("Domainmonster.com Privacy Service", response.TechnicalContact.Name);
            Assert.Equal("Identity Protect Limited", response.TechnicalContact.Organization);
            Assert.Equal("+44.1483307527", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+44.1483304031", response.TechnicalContact.FaxNumber);
            Assert.Equal("masala.xxx@privatemonster.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("PO Box 795", response.TechnicalContact.Address[0]);
            Assert.Equal("Godalming", response.TechnicalContact.Address[1]);
            Assert.Equal("Surrey", response.TechnicalContact.Address[2]);
            Assert.Equal("GU7 9GA", response.TechnicalContact.Address[3]);
            Assert.Equal("GB", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns39.domaincontrol.com", response.NameServers[0]);
            Assert.Equal("ns40.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(44, response.FieldsParsed);
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.xxx", "xxx", "reserved.txt");
            var response = parser.Parse("whois.nic.xxx", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.xxx/xxx/Reserved", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }
    }
}
