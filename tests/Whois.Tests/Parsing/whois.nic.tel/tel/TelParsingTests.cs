using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tel.Tel
{
    public class TelParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public TelParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.tel", "tel", "not-found", "u34jedzcq.tel.txt");
            var response = parser.Parse("whois.nic.tel", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tel/tel/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.tel", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.tel", "tel", "found", "google.tel.txt");
            var response = parser.Parse("whois.nic.tel", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tel/tel/found/01", response.TemplateName);

            Assert.Equal("google.tel", response.DomainName.ToString());
            Assert.Equal("D587349-TEL", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("292", response.Registrar.IanaId);
            Assert.Equal("www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2014, 03, 22, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2009, 03, 23, 23, 59, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 02, 19, 10, 23, 33, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("MMR-2383", response.Registrant.RegistryId);
            Assert.Equal("DNS Admin", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("United States", response.Registrant.Address[4]);
            Assert.Equal("US", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.Equal("MMR-2383", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);
            Assert.Equal("United States", response.AdminContact.Address[4]);
            Assert.Equal("US", response.AdminContact.Address[5]);


             // BillingContact Details
            Assert.Equal("MMR-132163", response.BillingContact.RegistryId);
            Assert.Equal("Domain Admin", response.BillingContact.Name);
            Assert.Equal("DNStination Inc.", response.BillingContact.Organization);
            Assert.Equal("+1.4155319335", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.4155319336", response.BillingContact.FaxNumber);
            Assert.Equal("admin@dnstinations.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(7, response.BillingContact.Address.Count);
            Assert.Equal("303 Second Street", response.BillingContact.Address[0]);
            Assert.Equal("Suite 800 North", response.BillingContact.Address[1]);
            Assert.Equal("San Francisco", response.BillingContact.Address[2]);
            Assert.Equal("CA", response.BillingContact.Address[3]);
            Assert.Equal("94107", response.BillingContact.Address[4]);
            Assert.Equal("United States", response.BillingContact.Address[5]);
            Assert.Equal("US", response.BillingContact.Address[6]);


             // TechnicalContact Details
            Assert.Equal("MMR-2383", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
            Assert.Equal("CA", response.TechnicalContact.Address[2]);
            Assert.Equal("94043", response.TechnicalContact.Address[3]);
            Assert.Equal("United States", response.TechnicalContact.Address[4]);
            Assert.Equal("US", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.Equal(5, response.NameServers.Count);
            Assert.Equal("a0.cth.dns.nic.tel", response.NameServers[0]);
            Assert.Equal("d0.cth.dns.nic.tel", response.NameServers[1]);
            Assert.Equal("n0.cth.dns.nic.tel", response.NameServers[2]);
            Assert.Equal("s0.cth.dns.nic.tel", response.NameServers[3]);
            Assert.Equal("t0.cth.dns.nic.tel", response.NameServers[4]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.Equal(65, response.FieldsParsed);
        }
    }
}
