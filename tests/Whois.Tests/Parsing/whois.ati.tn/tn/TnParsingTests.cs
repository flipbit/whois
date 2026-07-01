using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ati.Tn.Tn
{
    [TestFixture]
    public class TnParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.ati.tn", "tn", "found.txt");
            var response = parser.Parse("whois.ati.tn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(18, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ati.tn/tn/Found", response.TemplateName);

            Assert.AreEqual("equipements-pro.com.tn", response.DomainName.ToString());

            Assert.AreEqual("I-HOSTERS", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 12, 13, 22, 15, 8), response.Registered);
            Assert.AreEqual("MAISON DE BIEN HOTELIERS ET EQ Farhat Riadh", response.Registrant.Name);

            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("complexe commercial Boukris 2 rue Om Larayes", response.Registrant.Address[0]);

            Assert.AreEqual("98639096", response.Registrant.TelephoneNumber);
            Assert.AreEqual("mbh@tunet.tn", response.Registrant.Email);

            Assert.AreEqual("MAISON DE BIEN HOTELIERS ET EQ Farhat Riadh", response.AdminContact.Name);

            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("complexe commercial Boukris 2 rue Om Larayes", response.AdminContact.Address[0]);

            Assert.AreEqual("98639096", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("mbh@tunet.tn", response.AdminContact.Email);

            Assert.AreEqual("MAISON DE BIEN HOTELIERS ET EQ Farhat Riadh", response.TechnicalContact.Name);

            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("complexe commercial Boukris 2 rue Om Larayes", response.TechnicalContact.Address[0]);

            Assert.AreEqual("98639096", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("mbh@tunet.tn", response.TechnicalContact.Email);


            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns.steerbook.com", response.NameServers[0]);
            Assert.AreEqual("dns.steerbook.com", response.NameServers[1]);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.ati.tn", "tn", "not_found.txt");
            var response = parser.Parse("whois.ati.tn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(2, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ati.tn/tn/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.tn", response.DomainName.ToString());        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.ati.tn", "tn", "found_status_registered.txt");
            var response = parser.Parse("whois.ati.tn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(23, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ati.tn/tn/Found", response.TemplateName);

            Assert.AreEqual("google.tn", response.DomainName.ToString());

            Assert.AreEqual("3S Global Net", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 5, 14, 0, 0, 0), response.Registered);
            Assert.AreEqual("GOOGLE Inc", response.Registrant.Name);

            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("PO BOX 2050 Moutain view CA 94042 USA", response.Registrant.Address[0]);

            Assert.AreEqual("+1 925 685 9600", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1 925 685 9620", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

            Assert.AreEqual("GOOGLE Inc", response.AdminContact.Name);

            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("PO BOX 2050 Moutain view CA 94042 USA", response.AdminContact.Address[0]);

            Assert.AreEqual("+1 925 685 9600", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1 925 685 9620", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

            Assert.AreEqual("GOOGLE Inc", response.TechnicalContact.Name);

            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("PO BOX 2050 Moutain view CA 94042 USA", response.TechnicalContact.Address[0]);

            Assert.AreEqual("+1 925 685 9600", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1 925 685 9620", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);


            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);        }
    }
}
