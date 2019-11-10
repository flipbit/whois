using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nc.Nc
{
    [TestFixture]
    public class NcParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "found.txt");
            var response = parser.Parse("whois.nc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nc/nc/Found", response.TemplateName);

            Assert.AreEqual("rya.nc", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 03, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2013, 03, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 03, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("PLAY NEW CALEDONIA", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("12 BOULEVARD VAUBAN", response.Registrant.Address[0]);
            Assert.AreEqual("BP 2839", response.Registrant.Address[1]);
            Assert.AreEqual("98846 NOUMEA CEDEX", response.Registrant.Address[2]);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.linode.com", response.NameServers[0]);
            Assert.AreEqual("ns2.linode.com", response.NameServers[1]);
            Assert.AreEqual("ns3.linode.com", response.NameServers[2]);

            Assert.AreEqual(12, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_without_state_and_address()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "found_contact_without_state_and_address.txt");
            var response = parser.Parse("whois.nc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nc/nc/Found", response.TemplateName);

            Assert.AreEqual("gouv.nc", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 10, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 10, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 10, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DTSI", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("BP 15101", response.Registrant.Address[0]);
            Assert.AreEqual("98804 NOUMEA CEDEX", response.Registrant.Address[1]);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.gouv.nc", response.NameServers[0]);
            Assert.AreEqual("ns2.gouv.nc", response.NameServers[1]);
            Assert.AreEqual("ns3.gouv.nc", response.NameServers[2]);

            Assert.AreEqual(11, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "not_found.txt");
            var response = parser.Parse("whois.nc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound06", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "found_status_registered.txt");
            var response = parser.Parse("whois.nc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nc/nc/Found", response.TemplateName);

            Assert.AreEqual("domaine.nc", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 04, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 05, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2016, 05, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("CCTLD", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1 RUE MONCHOVET", response.Registrant.Address[0]);
            Assert.AreEqual("7 EME ETAGE", response.Registrant.Address[1]);
            Assert.AreEqual("LE WARUNA 1", response.Registrant.Address[2]);
            Assert.AreEqual("98841 NOUMEA CEDEX", response.Registrant.Address[3]);
            Assert.AreEqual("NEW CALEDONIA", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("any-ns1.nc", response.NameServers[0]);
            Assert.AreEqual("ns1.nc", response.NameServers[1]);
            Assert.AreEqual("ns2.nc", response.NameServers[2]);

            Assert.AreEqual(14, response.FieldsParsed);
        }
    }
}
