using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tld.Ee.Ee
{
    [TestFixture]
    public class EeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_serverhold()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "other_status_serverhold.txt");
            var response = parser.Parse("whois.tld.ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Expired, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tld.ee/ee/Found", response.TemplateName);

            Assert.AreEqual("samanacrafts.ee", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Edicy OÜ", response.Registrar.Name);
            Assert.AreEqual("http://www.edicy.com", response.Registrar.Url);
            Assert.AreEqual("+3727460064", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 11, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Anastassia Hisamova", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.Registrant.Updated);


             // AdminContact Details
            Assert.AreEqual("Anastassia Hisamova", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.AdminContact.Updated);


             // TechnicalContact Details
            Assert.AreEqual(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("ns4.edicy.net", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("expired", response.DomainStatus[0]);
            Assert.AreEqual("serverHold", response.DomainStatus[1]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "not_found.txt");
            var response = parser.Parse("whois.tld.ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound003", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_expired()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "expired.txt");
            var response = parser.Parse("whois.tld.ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Expired, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tld.ee/ee/Found", response.TemplateName);

            Assert.AreEqual("eestiinternet.ee", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Elisa Eesti AS", response.Registrar.Name);
            Assert.AreEqual("http://www.elisa.ee", response.Registrar.Url);
            Assert.AreEqual("+372 660 0600", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2010, 11, 29, 11, 32, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 07, 04, 04, 52, 56, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 11, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Eesti Interneti Sihtasutus", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2010, 11, 29, 11, 32, 16, 000, DateTimeKind.Utc), response.Registrant.Updated);


             // AdminContact Details
            Assert.AreEqual("Jaana Järve", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2015, 10, 30, 06, 31, 21, 000, DateTimeKind.Utc), response.AdminContact.Updated);


             // TechnicalContact Details
            Assert.AreEqual("Jaana Järve", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2015, 10, 30, 06, 31, 21, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("c.tld.ee", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("expired", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "found.txt");
            var response = parser.Parse("whois.tld.ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tld.ee/ee/Found", response.TemplateName);

            Assert.AreEqual("internet.ee", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Elisa Eesti AS", response.Registrar.Name);
            Assert.AreEqual("http://www.elisa.ee", response.Registrar.Url);
            Assert.AreEqual("+372 660 0600", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2010, 11, 29, 11, 32, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 08, 10, 13, 43, 38, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 02, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Eesti Interneti Sihtasutus", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2010, 11, 29, 11, 32, 16, 000, DateTimeKind.Utc), response.Registrant.Updated);


             // AdminContact Details
            Assert.AreEqual("Jaana Järve", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2015, 10, 30, 06, 31, 21, 000, DateTimeKind.Utc), response.AdminContact.Updated);


             // TechnicalContact Details
            Assert.AreEqual("Jaana Järve", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2015, 10, 30, 06, 31, 21, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("c.tld.ee", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok (paid and in zone)", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }
    }
}
