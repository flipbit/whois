using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.BrCom
{
    public class BrComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public BrComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "br.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "br.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/Found", response.TemplateName);

            Assert.Equal("billboard.br.com", response.DomainName.ToString());
            Assert.Equal("CNIC-DO624205", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Network Solutions LLC", response.Registrar.Name);
            Assert.Equal("http://www.networksolutions.com/", response.Registrar.Url);
            Assert.Equal("+1.9046806600", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2012, 1, 16, 16, 23, 18, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2009, 4, 17, 12, 22, 49, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2017, 4, 17, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("36542943", response.Registrant.RegistryId);
            Assert.Equal("Antonio Camarotti Pinto", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Rua Urussui, 238", response.Registrant.Address[0]);
            Assert.Equal("#22", response.Registrant.Address[1]);
            Assert.Equal("Sao Paulo", response.Registrant.Address[2]);
            Assert.Equal("Sao Paulo", response.Registrant.Address[3]);
            Assert.Equal("04542-050", response.Registrant.Address[4]);
            Assert.Equal("BR", response.Registrant.Address[5]);

            Assert.Equal("+1.551130787711", response.Registrant.TelephoneNumber);
            Assert.Equal("ac@bpp.bz", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("36542943", response.AdminContact.RegistryId);
            Assert.Equal("Antonio Camarotti Pinto", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("Rua Urussui, 238", response.AdminContact.Address[0]);
            Assert.Equal("#22", response.AdminContact.Address[1]);
            Assert.Equal("Sao Paulo", response.AdminContact.Address[2]);
            Assert.Equal("Sao Paulo", response.AdminContact.Address[3]);
            Assert.Equal("04542-050", response.AdminContact.Address[4]);
            Assert.Equal("BR", response.AdminContact.Address[5]);

            Assert.Equal("+1.551130787711", response.AdminContact.TelephoneNumber);
            Assert.Equal("ac@bpp.bz", response.AdminContact.Email);


             // BillingContact Details
            Assert.Equal("36542943", response.BillingContact.RegistryId);
            Assert.Equal("Antonio Camarotti Pinto", response.BillingContact.Name);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("Rua Urussui, 238", response.BillingContact.Address[0]);
            Assert.Equal("Sao Paulo", response.BillingContact.Address[1]);
            Assert.Equal("Sao Paulo", response.BillingContact.Address[2]);
            Assert.Equal("04542-050", response.BillingContact.Address[3]);
            Assert.Equal("BR", response.BillingContact.Address[4]);

            Assert.Equal("+1.551130787711", response.BillingContact.TelephoneNumber);
            Assert.Equal("ac@bpp.bz", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("36542943", response.TechnicalContact.RegistryId);
            Assert.Equal("Antonio Camarotti Pinto", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("Rua Urussui, 238", response.TechnicalContact.Address[0]);
            Assert.Equal("#22", response.TechnicalContact.Address[1]);
            Assert.Equal("Sao Paulo", response.TechnicalContact.Address[2]);
            Assert.Equal("Sao Paulo", response.TechnicalContact.Address[3]);
            Assert.Equal("04542-050", response.TechnicalContact.Address[4]);
            Assert.Equal("BR", response.TechnicalContact.Address[5]);

            Assert.Equal("+1.551130787711", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("ac@bpp.bz", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.locaweb.com.br", response.NameServers[0]);
            Assert.Equal("ns2.locaweb.com.br", response.NameServers[1]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("renewPeriod", response.DomainStatus[2]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(55, response.FieldsParsed);
        }
    }
}
