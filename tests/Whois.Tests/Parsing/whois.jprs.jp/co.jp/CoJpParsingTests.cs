using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.CoJp
{
    [TestFixture]
    public class CoJpParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "pending_delete.txt");
            var response = parser.Parse("whois.jprs.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/Found01", response.TemplateName);

            Assert.AreEqual("gaylife.co.jp", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 08, 08, 12, 00, 43, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.AreEqual("Suspended Domain Name", response.Registrant.Name);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Deleted", response.DomainStatus[0]);

            Assert.AreEqual(5, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "found.txt");
            var response = parser.Parse("whois.jprs.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/Found01", response.TemplateName);

            Assert.AreEqual("ahoo.co.jp", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 07, 08, 16, 50, 07, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2013, 03, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("yamazakipan corp.", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("TY20986JP", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.AreEqual("TY20986JP", response.TechnicalContact.RegistryId);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered", response.DomainStatus[0]);

            Assert.AreEqual(8, response.FieldsParsed);
        }

        [Test]
        public void Test_found_amazon_co_jp()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "amazon.co.jp.txt");

            var response = parser.Parse("whois.jprs.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/Found01", response.TemplateName);

            Assert.AreEqual("amazon.co.jp", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2018, 12, 01, 01, 01, 57, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 11, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Amazon, Inc.", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("JC076JP", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.AreEqual("IK4644JP", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.p31.dynect.net", response.NameServers[0]);
            Assert.AreEqual("ns2.p31.dynect.net", response.NameServers[1]);
            Assert.AreEqual("pdns1.ultradns.net", response.NameServers[2]);
            Assert.AreEqual("pdns6.ultradns.co.uk", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Connected", response.DomainStatus[0]);

            Assert.AreEqual(12, response.FieldsParsed);
        }
    }
}
