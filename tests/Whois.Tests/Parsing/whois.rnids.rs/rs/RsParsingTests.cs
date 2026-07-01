using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Rnids.Rs.Rs
{
    [TestFixture]
    public class RsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "found.txt");
            var response = parser.Parse("whois.rnids.rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rnids.rs/rs/Found", response.TemplateName);

            Assert.AreEqual("eg.rs", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("GAMA Electronics d.o.o.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 08, 08, 11, 13, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 10, 22, 10, 20, 31, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 10, 22, 10, 20, 31, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("bits-hq.bitsyu.net", response.NameServers[0]);
            Assert.AreEqual("largo.bitsyu.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(9, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_hyphenated()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "found_nameservers_hyphenated.txt");
            var response = parser.Parse("whois.rnids.rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rnids.rs/rs/Found", response.TemplateName);

            Assert.AreEqual("eg.rs", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("GAMA Electronics d.o.o.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 08, 08, 11, 13, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 10, 22, 10, 20, 31, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 10, 22, 10, 20, 31, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("bits-hq.bitsyu.net", response.NameServers[0]);
            Assert.AreEqual("largo.bitsyu.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(9, response.FieldsParsed);
        }

        [Test]
        public void Test_expired()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "expired.txt");
            var response = parser.Parse("whois.rnids.rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Expired, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rnids.rs/rs/Found", response.TemplateName);

            Assert.AreEqual("saj.rs", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("BGSVETIONIK.S.A.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 06, 18, 02, 00, 02, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 06, 17, 14, 40, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 06, 17, 14, 40, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Ana Rakovic", response.Registrant.Name);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns9.sajthosting.com", response.NameServers[0]);
            Assert.AreEqual("ns10.sajthosting.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Expired", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_in_transfer()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "other_status_in_transfer.txt");
            var response = parser.Parse("whois.rnids.rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rnids.rs/rs/Found", response.TemplateName);

            Assert.AreEqual("saj.rs", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NINET Company d.o.o.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 07, 06, 16, 24, 55, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 06, 17, 14, 40, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 06, 17, 14, 40, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Ana Rakovic", response.Registrant.Name);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.bgsvetionik.com", response.NameServers[0]);
            Assert.AreEqual("ns2.bgsvetionik.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("In Transfer", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }

        [Test]
        public void Test_locked()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "locked.txt");
            var response = parser.Parse("whois.rnids.rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Locked, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rnids.rs/rs/Found", response.TemplateName);

            Assert.AreEqual("kondor.rs", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("BGSVETIONIK.S.A.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 11, 18, 16, 03, 46, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 09, 30, 16, 19, 08, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 09, 30, 16, 19, 08, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Slavisa Janjusevic", response.Registrant.Name);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("dns1.orion.rs", response.NameServers[0]);
            Assert.AreEqual("dns2.orion.rs", response.NameServers[1]);
            Assert.AreEqual("dns3.orion.rs", response.NameServers[2]);
            Assert.AreEqual("dns4.orion.rs", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Locked", response.DomainStatus[0]);

            Assert.AreEqual(12, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "not_found.txt");
            var response = parser.Parse("whois.rnids.rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rnids.rs/rs/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "found_status_registered.txt");
            var response = parser.Parse("whois.rnids.rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Locked, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rnids.rs/rs/Found", response.TemplateName);

            Assert.AreEqual("google.rs", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NINET Company d.o.o.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 02, 11, 19, 49, 38, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 03, 10, 12, 31, 19, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 03, 10, 12, 31, 19, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway, Mountain View, United States of America", response.Registrant.Address[0]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Locked", response.DomainStatus[0]);

            Assert.AreEqual(13, response.FieldsParsed);
        }
    }
}
