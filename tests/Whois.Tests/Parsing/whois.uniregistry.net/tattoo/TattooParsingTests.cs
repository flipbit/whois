using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Uniregistry.Net.Tattoo
{
    public class TattooParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public TattooParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "not-found", "not_found.txt");
            var response = parser.Parse("whois.uniregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.uniregistry.net/tattoo/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.tattoo", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "found", "nic.tattoo.txt");
            var response = parser.Parse("whois.uniregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("nic.tattoo", response.DomainName.ToString());
            Assert.Equal("DO_4810ec9890fdf872f2e23b58df485dc4-ISC", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Uniregistry, Corp.", response.Registrar.Name);
            Assert.Equal("9999", response.Registrar.IanaId);
            Assert.Equal("http://whois.uniregistry.net", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 11, 09, 02, 51, 24, 230, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2013, 09, 16, 14, 21, 26, 648, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2023, 09, 16, 14, 21, 26, 648, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("uniregistry", response.Registrant.RegistryId);
            Assert.Equal("Uniregistry Registry Internal Resources", response.Registrant.Name);
            Assert.Equal("Uniregistry, Corp", response.Registrant.Organization);
            Assert.Equal("+1.3457496263", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.3457496263", response.Registrant.FaxNumber);
            Assert.Equal("info+whois@uniregistry.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("PO Box 1361", response.Registrant.Address[0]);
            Assert.Equal("Grand Cayman", response.Registrant.Address[1]);
            Assert.Equal("George Town", response.Registrant.Address[2]);
            Assert.Equal("KY1-1108", response.Registrant.Address[3]);
            Assert.Equal("KY", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("tattoo-admin", response.AdminContact.RegistryId);
            Assert.Equal("Uniregistry admin contact", response.AdminContact.Name);
            Assert.Equal("Uniregistry, Corp", response.AdminContact.Organization);
            Assert.Equal("+1.3457496263", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.3457496263", response.AdminContact.FaxNumber);
            Assert.Equal("admin@nic.tattoo", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("PO Box 1361", response.AdminContact.Address[0]);
            Assert.Equal("Grand Cayman", response.AdminContact.Address[1]);
            Assert.Equal("George Town", response.AdminContact.Address[2]);
            Assert.Equal("KY1-1108", response.AdminContact.Address[3]);
            Assert.Equal("KY", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("tattoo-billing", response.BillingContact.RegistryId);
            Assert.Equal("Uniregistry billing contact", response.BillingContact.Name);
            Assert.Equal("Uniregistry, Corp", response.BillingContact.Organization);
            Assert.Equal("+1.3457496263", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.3457496263", response.BillingContact.FaxNumber);
            Assert.Equal("billing@nic.tattoo", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("PO Box 1361", response.BillingContact.Address[0]);
            Assert.Equal("Grand Cayman", response.BillingContact.Address[1]);
            Assert.Equal("George Town", response.BillingContact.Address[2]);
            Assert.Equal("KY1-1108", response.BillingContact.Address[3]);
            Assert.Equal("KY", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("tattoo-tech", response.TechnicalContact.RegistryId);
            Assert.Equal("Uniregistry tech contact", response.TechnicalContact.Name);
            Assert.Equal("Uniregistry, Corp", response.TechnicalContact.Organization);
            Assert.Equal("+1.3457496263", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.3457496263", response.TechnicalContact.FaxNumber);
            Assert.Equal("tech@nic.tattoo", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("PO Box 1361", response.TechnicalContact.Address[0]);
            Assert.Equal("Grand Cayman", response.TechnicalContact.Address[1]);
            Assert.Equal("George Town", response.TechnicalContact.Address[2]);
            Assert.Equal("KY1-1108", response.TechnicalContact.Address[3]);
            Assert.Equal("KY", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("a.ns.uniregistry.net", response.NameServers[0]);
            Assert.Equal("tld.isc-sns.info", response.NameServers[1]);
            Assert.Equal("tld.isc-sns.com", response.NameServers[2]);
            Assert.Equal("tld.isc-sns.net", response.NameServers[3]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("serverDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("serverUpdateProhibited", response.DomainStatus[2]);

            Assert.Equal("signedDelegation", response.DnsSecStatus);
            Assert.Equal(62, response.FieldsParsed);
        }

        [Fact]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "unavailable", "unavailable.txt");
            var response = parser.Parse("whois.uniregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Unavailable, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.uniregistry.net/tattoo/unavailable/01", response.TemplateName);

            Assert.Equal("cheap.tattoo", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }
    }
}
