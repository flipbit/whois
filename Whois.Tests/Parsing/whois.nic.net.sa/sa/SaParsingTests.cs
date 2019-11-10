using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Net.Sa.Sa
{
    [TestFixture]
    public class SaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.net.sa", "sa", "not_found.txt");
            var response = parser.Parse("whois.nic.net.sa", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.net.sa/sa/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.com.sa", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.net.sa", "sa", "found.txt");
            var response = parser.Parse("whois.nic.net.sa", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.net.sa/sa/Found", response.TemplateName);

            Assert.AreEqual("saudigazette.com.sa", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2000, 09, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 09, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Okaz for Press and Publication مؤسسة عكاظ للصحافة والنشر", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("~noAddress  P.O.Box. 1508 ص.ب.", response.Registrant.Address[0]);
            Assert.AreEqual("21441 Jeddah جدة", response.Registrant.Address[1]);
            Assert.AreEqual("Saudi Arabia المملكة العربية السعودية", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Abdullah Salmeem Ba-Doukhn عبد الله سالمين بادخن (ADM-837-AD59-SA)", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("حي الرحاب  P.O.Box. 1508 ص.ب.", response.AdminContact.Address[0]);
            Assert.AreEqual("21441 Jeddah جدة", response.AdminContact.Address[1]);
            Assert.AreEqual("Saudi Arabia المملكة العربية السعودية", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("Salim Ba-wafi سالم باوافي (TEC-837-SW13-SA)", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("حي الرحاب  P.O.Box. 1508 ص.ب.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("21441 Jeddah جدة", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Saudi Arabia المملكة العربية السعودية", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.peer1.net", response.NameServers[0]);
            Assert.AreEqual("ns2.peer1.net", response.NameServers[1]);

            Assert.AreEqual(18, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
        }
    }
}
