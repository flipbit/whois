using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domainregistry.Ie.Ie
{
    public class IeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public IeParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "reserved.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domainregistry.ie/ie/Reserved", response.TemplateName);

            Assert.Equal("peter.ie", response.DomainName.ToString());

            Assert.Equal(new DateTime(2012, 04, 17, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_contacts_multiple()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_contacts_multiple.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);
            
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domainregistry.ie/ie/Found02", response.TemplateName);

            Assert.Equal("rte.ie", response.DomainName.ToString());

            Assert.Equal(new DateTime(2012, 03, 31, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("RTE Commercial Enterprises Limited", response.Registrant.Name);

             // AdminContact Details
            Assert.Equal("JL241-IEDR", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.Equal("JM474-IEDR", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns3.rte.ie", response.NameServers[0]);
            Assert.Equal("ns4.rte.ie", response.NameServers[1]);

            Assert.Equal(8, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_contacts_not_matching_id()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_contacts_not_matching_id.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domainregistry.ie/ie/Found", response.TemplateName);

            Assert.Equal("tcd.ie", response.DomainName.ToString());

            Assert.Equal(new DateTime(1999, 08, 24, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 08, 24, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("University of Dublin Trinity College", response.Registrant.Name);

             // AdminContact Details
            Assert.Equal("AAB502-IEDR", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.Equal("KG37-IEDR", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.Equal(6, response.NameServers.Count);
            Assert.Equal("ns1.tcd.ie", response.NameServers[0]);
            Assert.Equal("ns2.tcd.ie", response.NameServers[1]);
            Assert.Equal("ns.maths.tcd.ie", response.NameServers[2]);
            Assert.Equal("sec2.authdns.ripe.net", response.NameServers[3]);
            Assert.Equal("ns.tcd.ie", response.NameServers[4]);
            Assert.Equal("auth-ns1.ucd.ie", response.NameServers[5]);

            Assert.Equal(13, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domainregistry.ie/ie/Found02", response.TemplateName);

            Assert.Equal("dns.ie", response.DomainName.ToString());

            Assert.Equal(new DateTime(2021, 02, 20, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Irish Domains Ltd", response.Registrant.Name);

             // AdminContact Details
            Assert.Equal("CM417-IEDR", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.Equal("TDI2-IEDR", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.Equal(6, response.NameServers.Count);
            Assert.Equal("ns1.dns.ie", response.NameServers[0]);
            Assert.Equal("ns2.dns.ie", response.NameServers[1]);
            Assert.Equal("ns3.dns.ie", response.NameServers[2]);
            Assert.Equal("ns4.dns.ie", response.NameServers[3]);
            Assert.Equal("ns5.dns.ie", response.NameServers[4]);
            Assert.Equal("ns6.dns.ie", response.NameServers[5]);

            Assert.Equal(12, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "not_found.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domainregistry.ie/ie/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.ie", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_status_registered.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.domainregistry.ie/ie/Found", response.TemplateName);

            Assert.Equal("google.ie", response.DomainName.ToString());

            Assert.Equal(new DateTime(2002, 03, 21, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 03, 21, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google, Inc", response.Registrant.Name);

             // AdminContact Details
            Assert.Equal("AAV410-IEDR", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.Equal("CCA7-IEDR", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Active", response.DomainStatus[0]);

            Assert.Equal(11, response.FieldsParsed);
        }
    }
}
