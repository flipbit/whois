using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domainregistry.Ie.Ie
{
    [TestFixture]
    public class IeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "reserved.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domainregistry.ie/ie/Reserved", response.TemplateName);

            Assert.AreEqual("peter.ie", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 04, 17, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contacts_multiple()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_contacts_multiple.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);
            
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domainregistry.ie/ie/Found02", response.TemplateName);

            Assert.AreEqual("rte.ie", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 03, 31, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("RTE Commercial Enterprises Limited", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("JL241-IEDR", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.AreEqual("JM474-IEDR", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns3.rte.ie", response.NameServers[0]);
            Assert.AreEqual("ns4.rte.ie", response.NameServers[1]);

            Assert.AreEqual(8, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contacts_not_matching_id()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_contacts_not_matching_id.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domainregistry.ie/ie/Found", response.TemplateName);

            Assert.AreEqual("tcd.ie", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(1999, 08, 24, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 08, 24, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("University of Dublin Trinity College", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("AAB502-IEDR", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.AreEqual("KG37-IEDR", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns1.tcd.ie", response.NameServers[0]);
            Assert.AreEqual("ns2.tcd.ie", response.NameServers[1]);
            Assert.AreEqual("ns.maths.tcd.ie", response.NameServers[2]);
            Assert.AreEqual("sec2.authdns.ripe.net", response.NameServers[3]);
            Assert.AreEqual("ns.tcd.ie", response.NameServers[4]);
            Assert.AreEqual("auth-ns1.ucd.ie", response.NameServers[5]);

            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domainregistry.ie/ie/Found02", response.TemplateName);

            Assert.AreEqual("dns.ie", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2021, 02, 20, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Irish Domains Ltd", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("CM417-IEDR", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.AreEqual("TDI2-IEDR", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns1.dns.ie", response.NameServers[0]);
            Assert.AreEqual("ns2.dns.ie", response.NameServers[1]);
            Assert.AreEqual("ns3.dns.ie", response.NameServers[2]);
            Assert.AreEqual("ns4.dns.ie", response.NameServers[3]);
            Assert.AreEqual("ns5.dns.ie", response.NameServers[4]);
            Assert.AreEqual("ns6.dns.ie", response.NameServers[5]);

            Assert.AreEqual(12, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "not_found.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domainregistry.ie/ie/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ie", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_status_registered.txt");
            var response = parser.Parse("whois.domainregistry.ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domainregistry.ie/ie/Found", response.TemplateName);

            Assert.AreEqual("google.ie", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2002, 03, 21, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 03, 21, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google, Inc", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("AAV410-IEDR", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.AreEqual("CCA7-IEDR", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }
    }
}
