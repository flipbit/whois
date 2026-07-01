using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Priv.At.At
{
    [TestFixture]
    public class AtParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.priv.at", "at", "not_found.txt");
            var response = parser.Parse("whois.nic.priv.at", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.priv.at/at/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.priv.at", "at", "found.txt");
            var response = parser.Parse("whois.nic.priv.at", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.priv.at/at/Found", response.TemplateName);

            Assert.AreEqual("nic.priv.at", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Network Information Center for priv.at", response.Registrar.Name);
            Assert.AreEqual("hostmaster@nic.priv.at", response.Registrar.AbuseEmail);

            Assert.AreEqual(new DateTime(2002, 10, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.AreEqual("HM-PRIVAT", response.AdminContact.RegistryId);
            Assert.AreEqual("Hostmaster priv.at", response.AdminContact.Name);
            Assert.AreEqual("hostmaster@nic.priv.at", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("Verein fuer Internet-Benutzer Oesterreichs (VIBE!AT)", response.AdminContact.Address[0]);
            Assert.AreEqual("c/o Gerald Pfeifer", response.AdminContact.Address[1]);
            Assert.AreEqual("Mondweg 64", response.AdminContact.Address[2]);
            Assert.AreEqual("A-1140", response.AdminContact.Address[3]);
            Assert.AreEqual("Wien", response.AdminContact.Address[4]);
            Assert.AreEqual("Austria", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("HM-PRIVAT", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Hostmaster priv.at", response.TechnicalContact.Name);
            Assert.AreEqual("hostmaster@nic.priv.at", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Verein fuer Internet-Benutzer Oesterreichs (VIBE!AT)", response.TechnicalContact.Address[0]);
            Assert.AreEqual("c/o Gerald Pfeifer", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Mondweg 64", response.TechnicalContact.Address[2]);
            Assert.AreEqual("A-1140", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Wien", response.TechnicalContact.Address[4]);
            Assert.AreEqual("Austria", response.TechnicalContact.Address[5]);


             // ZoneContact Details
            Assert.AreEqual("HM-PRIVAT", response.ZoneContact.RegistryId);
            Assert.AreEqual("Hostmaster priv.at", response.ZoneContact.Name);
            Assert.AreEqual("hostmaster@nic.priv.at", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.AreEqual(6, response.ZoneContact.Address.Count);
            Assert.AreEqual("Verein fuer Internet-Benutzer Oesterreichs (VIBE!AT)", response.ZoneContact.Address[0]);
            Assert.AreEqual("c/o Gerald Pfeifer", response.ZoneContact.Address[1]);
            Assert.AreEqual("Mondweg 64", response.ZoneContact.Address[2]);
            Assert.AreEqual("A-1140", response.ZoneContact.Address[3]);
            Assert.AreEqual("Wien", response.ZoneContact.Address[4]);
            Assert.AreEqual("Austria", response.ZoneContact.Address[5]);


            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
