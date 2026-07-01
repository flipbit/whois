using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.Lk
{
    [TestFixture]
    public class LkParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.lk", "lk", "found.txt");
            var response = parser.Parse("whois.nic.lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.lk/Found01", response.TemplateName);

            Assert.AreEqual("nestle.lk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 03, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2019, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Nestle Lanka Ltd.", response.Registrant.Name);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("aoadns1.nestle.com.", response.NameServers[0]);
            Assert.AreEqual("ctrdns1.nestle.com.", response.NameServers[1]);
            Assert.AreEqual("ctrdns1.nestle.com.", response.NameServers[2]);

            Assert.AreEqual(8, response.FieldsParsed);
        }

        [Test]
        public void Test_found_updated_on_null()
        {
            var sample = SampleReader.Read("whois.nic.lk", "lk", "found_updated_on_null.txt");
            var response = parser.Parse("whois.nic.lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.lk/Found01", response.TemplateName);

            Assert.AreEqual("clear.lk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 11, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 11, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("WELIGAMA HOTEL PROPERTIES LIMITED", response.Registrant.Name);

            Assert.AreEqual(5, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.lk", "lk", "not_found.txt");
            var response = parser.Parse("whois.nic.lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.lk/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.lk", "lk", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.lk/Found01", response.TemplateName);

            Assert.AreEqual("google.lk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 03, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com.", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com.", response.NameServers[1]);

            Assert.AreEqual(8, response.FieldsParsed);
        }
    }
}
