using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Dz.Dz
{
    [TestFixture]
    public class DzParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.dz", "dz", "not_found.txt");
            var response = parser.Parse("whois.nic.dz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.dz/dz/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.dz", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.dz", "dz", "found.txt");
            var response = parser.Parse("whois.nic.dz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.dz/dz/Found", response.TemplateName);

            Assert.AreEqual("google.dz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("cerist", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2007, 01, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("GOOGLE LLC", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("GOOGLE LLC", response.AdminContact.Organization);
            Assert.AreEqual("+16502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+16502530000", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway, Mountain View, CA 94043 US", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("Domain AdmDomain Administratorinistrator", response.TechnicalContact.Name);
            Assert.AreEqual("MARKMONITOR INC", response.TechnicalContact.Organization);
            Assert.AreEqual("+12083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+12083895771", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Place Boise, ID 83704 US", response.TechnicalContact.Address[0]);


            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
