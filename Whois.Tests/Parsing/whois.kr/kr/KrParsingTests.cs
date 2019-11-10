using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Kr.Kr
{
    [TestFixture]
    public class KrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.kr", "kr", "found.txt");
            var response = parser.Parse("whois.kr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.kr/kr/Found", response.TemplateName);

            Assert.AreEqual("lg.co.kr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Whois Corp.(http://whois.co.kr)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 02, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1995, 03, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2021, 10, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("LG Corp.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("LG Twintower 20, Youido-dong, Youngdeungpo-gu,, Seoul", response.Registrant.Address[0]);
            Assert.AreEqual("150721", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.AreEqual("Domain-Manager", response.AdminContact.Name);
            Assert.AreEqual("02-3773-2322", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("young@lg.com", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("prmns.lg.co.kr", response.NameServers[0]);
            Assert.AreEqual("secns.lg.co.kr", response.NameServers[1]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.kr", "kr", "not_found.txt");
            var response = parser.Parse("whois.kr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.kr/kr/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.kr", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.kr", "kr", "found_status_registered.txt");
            var response = parser.Parse("whois.kr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.kr/kr/Found", response.TemplateName);

            Assert.AreEqual("google.kr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Whois Corp.(http://whois.co.kr)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 10, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 03, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 03, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Korea, LLC", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("22nd Floor Gangnam Finance Center, 737 Yeoksam-dong Kangnam-ku Seoul", response.Registrant.Address[0]);
            Assert.AreEqual("135984", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("82.25319000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            Assert.AreEqual(14, response.FieldsParsed);
        }
    }
}
