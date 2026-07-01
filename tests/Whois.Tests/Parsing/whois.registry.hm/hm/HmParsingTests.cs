using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Hm.Hm
{
    public class HmParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public HmParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.registry.hm", "hm", "not_found.txt");
            var response = parser.Parse("whois.registry.hm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound003", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registry.hm", "hm", "found.txt");
            var response = parser.Parse("whois.registry.hm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registry.hm/hm/Found", response.TemplateName);

            Assert.Equal("google.hm", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("HM Domain Registry", response.Registrar.Name);
            Assert.Equal("http://www.registry.hm/", response.Registrar.Url);

            Assert.Equal(new DateTime(2003, 04, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2020, 04, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("John G Rose", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1058 Jasmine St.", response.Registrant.Address[0]);
            Assert.Equal("Denver CO 80220", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("ROS00074", response.AdminContact.RegistryId);
            Assert.Equal("John Rose", response.AdminContact.Name);
            Assert.Equal("Sigma Polyplexic", response.AdminContact.Organization);
            Assert.Equal("2129996566", response.AdminContact.TelephoneNumber);
            Assert.Equal("johnrose@polyplexic.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("1058 Jasmine St.", response.AdminContact.Address[0]);
            Assert.Equal("Denver CO 80220", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.Equal("ROS00074", response.BillingContact.RegistryId);
            Assert.Equal("John Rose", response.BillingContact.Name);
            Assert.Equal("Sigma Polyplexic", response.BillingContact.Organization);
            Assert.Equal("2129996566", response.BillingContact.TelephoneNumber);
            Assert.Equal("johnrose@polyplexic.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(3, response.BillingContact.Address.Count);
            Assert.Equal("1058 Jasmine St.", response.BillingContact.Address[0]);
            Assert.Equal("Denver CO 80220", response.BillingContact.Address[1]);
            Assert.Equal("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("ROS00074", response.TechnicalContact.RegistryId);
            Assert.Equal("John Rose", response.TechnicalContact.Name);
            Assert.Equal("Sigma Polyplexic", response.TechnicalContact.Organization);
            Assert.Equal("2129996566", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("johnrose@polyplexic.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("1058 Jasmine St.", response.TechnicalContact.Address[0]);
            Assert.Equal("Denver CO 80220", response.TechnicalContact.Address[1]);
            Assert.Equal("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.everydns.net", response.NameServers[0]);
            Assert.Equal("ns2.everydns.net", response.NameServers[1]);

            Assert.Equal(36, response.FieldsParsed);
        }
    }
}
