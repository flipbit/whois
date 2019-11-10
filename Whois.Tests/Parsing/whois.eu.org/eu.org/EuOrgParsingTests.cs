using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Eu.Org.EuOrg
{
    [TestFixture]
    public class EuOrgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.eu.org", "eu.org", "not_found.txt");
            var response = parser.Parse("whois.eu.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.eu.org/eu.org/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.eu.org", "eu.org", "found.txt");
            var response = parser.Parse("whois.eu.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found03", response.TemplateName);

            Assert.AreEqual("google.eu.org", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2003, 03, 27, 23, 00, 00, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.AreEqual("Mueller Michael", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Wilhelm-Busch-Str. 35", response.Registrant.Address[0]);
            Assert.AreEqual("32108 Bad Salzuflen", response.Registrant.Address[1]);
            Assert.AreEqual("Germany", response.Registrant.Address[2]);

             // AdminContact Details
            Assert.AreEqual("MM114-FREE", response.AdminContact.RegistryId);
            Assert.AreEqual("Mueller Michael", response.AdminContact.Name);
            Assert.AreEqual("+49 005222 94569", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("mm114-d7ea0ef920c90b777acb325103212a7c@handles.eu.org", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Wilhelm-Busch-Str. 35", response.AdminContact.Address[0]);
            Assert.AreEqual("32108 Bad Salzuflen", response.AdminContact.Address[1]);
            Assert.AreEqual("Germany", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("MM114-FREE", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Mueller Michael", response.TechnicalContact.Name);
            Assert.AreEqual("+49 005222 94569", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("mm114-d7ea0ef920c90b777acb325103212a7c@handles.eu.org", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Wilhelm-Busch-Str. 35", response.TechnicalContact.Address[0]);
            Assert.AreEqual("32108 Bad Salzuflen", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Germany", response.TechnicalContact.Address[2]);

            Assert.AreEqual(16, response.FieldsParsed);
        }
    }
}
