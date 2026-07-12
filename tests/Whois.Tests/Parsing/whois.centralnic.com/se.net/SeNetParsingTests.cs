using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.SeNet
{
    public class SeNetParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public SeNetParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "se.net", "not-found", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "se.net", "found", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

            Assert.Equal("hotel.se.net", response.DomainName.ToString());
            Assert.Equal("CNIC-DO1617446", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Soluciones Corporativas IP, S.L.U.", response.Registrar.Name);
            Assert.Equal("1383", response.Registrar.IanaId);
            Assert.Equal("+34.871986600", response.Registrar.AbuseTelephoneNumber);
            Assert.Equal("www.scip.es", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 11, 28, 11, 49, 39, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2013, 11, 13, 10, 35, 3, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 11, 13, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("scipr000323588", response.Registrant.RegistryId);
            Assert.Equal("Christoph Donath", response.Registrant.Name);
            Assert.Equal("Christoph Donath", response.Registrant.Organization);
            Assert.Equal("+34.667889082", response.Registrant.TelephoneNumber);
            Assert.Equal("info@christophdonath.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("C. Tijarafe 24, 2c", response.Registrant.Address[0]);
            Assert.Equal("Cruce de Arinaga", response.Registrant.Address[1]);
            Assert.Equal("Palmas (Las)", response.Registrant.Address[2]);
            Assert.Equal("35118", response.Registrant.Address[3]);
            Assert.Equal("ES", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("scipa000323588", response.AdminContact.RegistryId);
            Assert.Equal("Christoph Donath", response.AdminContact.Name);
            Assert.Equal("Christoph Donath", response.AdminContact.Organization);
            Assert.Equal("+34.667889082", response.AdminContact.TelephoneNumber);
            Assert.Equal("info@christophdonath.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("C. Tijarafe 24, 2c", response.AdminContact.Address[0]);
            Assert.Equal("Cruce de Arinaga", response.AdminContact.Address[1]);
            Assert.Equal("Palmas (Las)", response.AdminContact.Address[2]);
            Assert.Equal("35118", response.AdminContact.Address[3]);
            Assert.Equal("ES", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("scipb000323588", response.BillingContact.RegistryId);
            Assert.Equal("Christoph Donath", response.BillingContact.Name);
            Assert.Equal("Christoph Donath", response.BillingContact.Organization);
            Assert.Equal("+34.667889082", response.BillingContact.TelephoneNumber);
            Assert.Equal("info@christophdonath.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("C. Tijarafe 24, 2c", response.BillingContact.Address[0]);
            Assert.Equal("Cruce de Arinaga", response.BillingContact.Address[1]);
            Assert.Equal("Palmas (Las)", response.BillingContact.Address[2]);
            Assert.Equal("35118", response.BillingContact.Address[3]);
            Assert.Equal("ES", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("scipt000323588", response.TechnicalContact.RegistryId);
            Assert.Equal("Christoph Donath", response.TechnicalContact.Name);
            Assert.Equal("Christoph Donath", response.TechnicalContact.Organization);
            Assert.Equal("+34.667889082", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("info@christophdonath.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("C. Tijarafe 24, 2c", response.TechnicalContact.Address[0]);
            Assert.Equal("Cruce de Arinaga", response.TechnicalContact.Address[1]);
            Assert.Equal("Palmas (Las)", response.TechnicalContact.Address[2]);
            Assert.Equal("35118", response.TechnicalContact.Address[3]);
            Assert.Equal("ES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns8261.hostgator.com", response.NameServers[0]);
            Assert.Equal("ns8262.hostgator.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(54, response.FieldsParsed);
        }
    }
}
