using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.In.Ua.InUa
{
    [TestFixture]
    public class InUaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.in.ua", "in.ua", "not_found.txt");
            var response = parser.Parse("whois.in.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.in.ua/in.ua/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.in.ua", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.in.ua", "in.ua", "found.txt");
            var response = parser.Parse("whois.in.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.in.ua/in.ua/Found", response.TemplateName);

            Assert.AreEqual("dle.in.ua", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 12, 16, 13, 41, 04, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.AreEqual("VP535-UANIC", response.AdminContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("NIC-UANIC", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns12.uadns.com", response.NameServers[0]);
            Assert.AreEqual("ns11.uadns.com", response.NameServers[1]);
            Assert.AreEqual("ns10.uadns.com", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK-UNTIL 20131218000000", response.DomainStatus[0]); // TODO: Parse Expiry date

            Assert.AreEqual(9, response.FieldsParsed);
        }
    }
}
