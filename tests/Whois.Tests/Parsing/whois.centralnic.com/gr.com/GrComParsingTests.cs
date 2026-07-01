using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.GrCom
{
    [TestFixture]
    public class GrComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "gr.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "gr.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("google.gr.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO735168", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2012, 6, 23, 10, 38, 2, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 2, 7, 13, 10, 14, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 2, 7, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1346485", response.Registrant.RegistryId);


             // BillingContact Details
            Assert.AreEqual("H1346485", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("H1346485", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("f1g1ns1.dnspod.net", response.NameServers[0]);
            Assert.AreEqual("f1g1ns2.dnspod.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(13, response.FieldsParsed);
        }
    }
}
