using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.AeOrg
{
    public class AeOrgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AeOrgParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "ae.org", "not-found", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "ae.org", "found", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

            Assert.Equal("kidzlink.ae.org", response.DomainName.ToString());
            Assert.Equal("CNIC-DO887354", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("101Domain, Inc.", response.Registrar.Name);
            Assert.Equal("http://www.101domain.com", response.Registrar.Url);
            Assert.Equal("+1.7604448674", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 6, 9, 0, 12, 37, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2012, 8, 3, 15, 37, 33, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 8, 3, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("RWG000000003DA24", response.Registrant.RegistryId);
            Assert.Equal("IPC C/O Clarenter", response.Registrant.Name);
            Assert.Equal("Clarenter", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("110 E Broward Blvd", response.Registrant.Address[0]);
            Assert.Equal("Ste. 1720", response.Registrant.Address[1]);
            Assert.Equal("Fort Lauderdale", response.Registrant.Address[2]);
            Assert.Equal("FL", response.Registrant.Address[3]);
            Assert.Equal("33301", response.Registrant.Address[4]);
            Assert.Equal("US", response.Registrant.Address[5]);

            Assert.Equal("+1.18888443911", response.Registrant.TelephoneNumber);
            Assert.Equal("patricia@internationalpreschoolcurriculum.com", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("RWG000000003DA24", response.AdminContact.RegistryId);
            Assert.Equal("IPC C/O Clarenter", response.AdminContact.Name);
            Assert.Equal("Clarenter", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("110 E Broward Blvd", response.AdminContact.Address[0]);
            Assert.Equal("Ste. 1720", response.AdminContact.Address[1]);
            Assert.Equal("Fort Lauderdale", response.AdminContact.Address[2]);
            Assert.Equal("FL", response.AdminContact.Address[3]);
            Assert.Equal("33301", response.AdminContact.Address[4]);
            Assert.Equal("US", response.AdminContact.Address[5]);

            Assert.Equal("+1.18888443911", response.AdminContact.TelephoneNumber);
            Assert.Equal("patricia@internationalpreschoolcurriculum.com", response.AdminContact.Email);


             // BillingContact Details
            Assert.Equal("RWG000000003DA25", response.BillingContact.RegistryId);
            Assert.Equal("Billing Department", response.BillingContact.Name);
            Assert.Equal("101Domain, Inc.", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("5858 Edison Pl.", response.BillingContact.Address[0]);
            Assert.Equal("Carlsbad", response.BillingContact.Address[1]);
            Assert.Equal("CA", response.BillingContact.Address[2]);
            Assert.Equal("92008", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);

            Assert.Equal("+1.7604448674", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.7605794996", response.BillingContact.FaxNumber);
            Assert.Equal("tech1@101domain.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("RWG000000003DA24", response.TechnicalContact.RegistryId);
            Assert.Equal("IPC C/O Clarenter", response.TechnicalContact.Name);
            Assert.Equal("Clarenter", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("110 E Broward Blvd", response.TechnicalContact.Address[0]);
            Assert.Equal("Ste. 1720", response.TechnicalContact.Address[1]);
            Assert.Equal("Fort Lauderdale", response.TechnicalContact.Address[2]);
            Assert.Equal("FL", response.TechnicalContact.Address[3]);
            Assert.Equal("33301", response.TechnicalContact.Address[4]);
            Assert.Equal("US", response.TechnicalContact.Address[5]);

            Assert.Equal("+1.18888443911", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("patricia@internationalpreschoolcurriculum.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns37.domaincontrol.com", response.NameServers[0]);
            Assert.Equal("ns38.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(59, response.FieldsParsed);
        }
    }
}
