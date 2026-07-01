using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.QcCom
{
    [TestFixture]
    public class QcComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "qc.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "qc.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("ceo.qc.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO327026", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("eNom, Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.enom.com/", response.Registrar.Url);
            Assert.AreEqual("425-274-4500", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2012, 11, 23, 18, 3, 55, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 10, 8, 2, 12, 49, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 10, 8, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1062277", response.Registrant.RegistryId);
            Assert.AreEqual("helene", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("309 Laurendeau, Magog Qc", response.Registrant.Address[0]);
            Assert.AreEqual("J1X 3W4", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);

            Assert.AreEqual("+1.8198438380", response.Registrant.TelephoneNumber);
            Assert.AreEqual("docjgs@videotron.ca", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("H114589", response.AdminContact.RegistryId);
            Assert.AreEqual("helene viens", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("309 Laurendeau, Magog Qc", response.AdminContact.Address[0]);
            Assert.AreEqual("J1X 3W4", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);

            Assert.AreEqual("+1.8198438380", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("docjgs@videotron.ca", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("H114590", response.TechnicalContact.RegistryId);
            Assert.AreEqual("helene viens", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("309 Laurendeau, Magog Qc", response.TechnicalContact.Address[0]);
            Assert.AreEqual("J1X 3W4", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);

            Assert.AreEqual("+1.8198438380", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("docjgs@videotron.ca", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns12.zoneedit.com", response.NameServers[0]);
            Assert.AreEqual("t1.zoneedit.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(35, response.FieldsParsed);
        }
    }
}
