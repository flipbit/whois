using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dotname.Co.Kr.Com
{
    [TestFixture]
    public class ComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dotname.co.kr", "com", "found.txt");
            
            var response = parser.Parse("whois.dotname.co.kr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found02", response.TemplateName);

            Assert.AreEqual("ggemtv.com", response.DomainName.ToString());
            Assert.AreEqual("2282446647_DOMAIN_COM-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Dotname Korea Corp.", response.Registrar.Name);
            Assert.AreEqual("1132", response.Registrar.IanaId);
            Assert.AreEqual("http://www.dotname.co.kr", response.Registrar.Url);
            Assert.AreEqual("whois.dotname.co.kr", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("abuse@dotnamekorea.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+82.7070900820", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2019, 07, 05, 03, 28, 02, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2018, 07, 05, 01, 48, 01, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 07, 05, 01, 48, 01, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns11.dnstool.net", response.NameServers[0]);
            Assert.AreEqual("ns12.dnstool.net", response.NameServers[1]);
            Assert.AreEqual("ns13.dnstool.net", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
