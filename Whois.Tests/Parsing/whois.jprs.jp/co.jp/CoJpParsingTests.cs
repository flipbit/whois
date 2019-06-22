using System;
using NUnit.Framework;
using Whois.Models;
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
            var response = parser.Parse("whois.jprs.jp", "co.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/co.jp/PendingDelete", response.TemplateName);

            Assert.AreEqual("gaylife.co.jp", response.DomainName);

            Assert.AreEqual(new DateTime(2012, 8, 8, 12, 0, 43), response.Updated);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Deleted (2013/01/31)", response.DomainStatus[0]);

            Assert.AreEqual(4, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "found.txt");
            var response = parser.Parse("whois.jprs.jp", "co.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/co.jp/Found", response.TemplateName);

            Assert.AreEqual("ahoo.co.jp", response.DomainName);

            Assert.AreEqual(new DateTime(2013, 7, 8, 16, 50, 7), response.Updated);
            Assert.AreEqual(new DateTime(2013, 3, 20, 0, 0, 0), response.Registered);

             // Registrant Details
            Assert.AreEqual("yamazakipan corp.", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("TY20986JP", response.AdminContact.Name);

             // TechnicalContact Details
            Assert.AreEqual("TY20986JP", response.TechnicalContact.Name);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered (2014/03/31)", response.DomainStatus[0]);

            Assert.AreEqual(8, response.FieldsParsed);
        }

        [Test]
        public void Test_found_amazon_co_jp()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "amazon.co.jp.txt");

            var response = parser.Parse("whois.jprs.jp", "co.jp", sample);

            AssertWriter.Write(response);

            Assert.AreEqual("amazon.co.jp", response.DomainName);
            Assert.AreEqual("Amazon, Inc.", response.Registrant.Name);
            Assert.AreEqual("JC076JP", response.AdminContact.Name);
            Assert.AreEqual("IK4644JP", response.TechnicalContact.Name);
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.p31.dynect.net", response.NameServers[0]);
            Assert.AreEqual("ns2.p31.dynect.net", response.NameServers[1]);
            Assert.AreEqual("pdns1.ultradns.net", response.NameServers[2]);
            Assert.AreEqual("pdns6.ultradns.co.uk", response.NameServers[3]);
            Assert.AreEqual(new DateTime(2002, 11, 21), response.Registered);
            Assert.AreEqual(new DateTime(2018, 12, 01, 01, 01, 57), response.Updated);
        }
    }
}
