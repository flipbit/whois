using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.JpNet
{
    public class JpNetParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public JpNetParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "jp.net", "not-found", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "jp.net", "found", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

            Assert.Equal("ntt.jp.net", response.DomainName.ToString());
            Assert.Equal("CNIC-DO846061", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("GMO", response.Registrar.Name);
            Assert.Equal("http://www.onamae.com", response.Registrar.Url);
            Assert.Equal("+81 3 5456 1120", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 1, 24, 16, 57, 19, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2012, 3, 16, 11, 47, 23, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2018, 3, 16, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("136151BCEFE", response.Registrant.RegistryId);
            Assert.Equal("zhijian xia", response.Registrant.Name);
            Assert.Equal("zhijian xia", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Chuo", response.Registrant.Address[0]);
            Assert.Equal("3-23-20", response.Registrant.Address[1]);
            Assert.Equal("Warabi-shi", response.Registrant.Address[2]);
            Assert.Equal("Saitama", response.Registrant.Address[3]);
            Assert.Equal("335-0004", response.Registrant.Address[4]);
            Assert.Equal("JP", response.Registrant.Address[5]);

            Assert.Equal("+81.08037215656", response.Registrant.TelephoneNumber);
            Assert.Equal("xia@ingame.jp", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("136151BD1A1", response.AdminContact.RegistryId);
            Assert.Equal("zhijian xia", response.AdminContact.Name);
            Assert.Equal("zhijian xia", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("Chuo", response.AdminContact.Address[0]);
            Assert.Equal("3-23-20", response.AdminContact.Address[1]);
            Assert.Equal("Warabi-shi", response.AdminContact.Address[2]);
            Assert.Equal("Saitama", response.AdminContact.Address[3]);
            Assert.Equal("335-0004", response.AdminContact.Address[4]);
            Assert.Equal("JP", response.AdminContact.Address[5]);

            Assert.Equal("+81.08037215656", response.AdminContact.TelephoneNumber);
            Assert.Equal("xia@ingame.jp", response.AdminContact.Email);


             // BillingContact Details
            Assert.Equal("136151BD74A", response.BillingContact.RegistryId);
            Assert.Equal("zhijian xia", response.BillingContact.Name);
            Assert.Equal("zhijian xia", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("Chuo", response.BillingContact.Address[0]);
            Assert.Equal("Warabi-shi", response.BillingContact.Address[1]);
            Assert.Equal("Saitama", response.BillingContact.Address[2]);
            Assert.Equal("335-0004", response.BillingContact.Address[3]);
            Assert.Equal("JP", response.BillingContact.Address[4]);

            Assert.Equal("+81.08037215656", response.BillingContact.TelephoneNumber);
            Assert.Equal("xia@ingame.jp", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("136151BD459", response.TechnicalContact.RegistryId);
            Assert.Equal("Technical Contact", response.TechnicalContact.Name);
            Assert.Equal("GMO Internet Inc.", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("26-1 Sakuragaoka-cho", response.TechnicalContact.Address[0]);
            Assert.Equal("Cerulean Tower 11F", response.TechnicalContact.Address[1]);
            Assert.Equal("Shibuya-ku", response.TechnicalContact.Address[2]);
            Assert.Equal("Tokyo", response.TechnicalContact.Address[3]);
            Assert.Equal("150-8512", response.TechnicalContact.Address[4]);
            Assert.Equal("JP", response.TechnicalContact.Address[5]);

            Assert.Equal("+81.0354562555", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("admin@onamae.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("dns1.onamae.com", response.NameServers[0]);
            Assert.Equal("dns2.onamae.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(57, response.FieldsParsed);
        }
    }
}
