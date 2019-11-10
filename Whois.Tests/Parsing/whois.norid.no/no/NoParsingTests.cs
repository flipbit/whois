using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Norid.No.No
{
    [TestFixture]
    public class NoParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.norid.no", "no", "not_found.txt");
            var response = parser.Parse("whois.norid.no", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.norid.no/no/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.norid.no", "no", "found.txt");
            var response = parser.Parse("whois.norid.no", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.norid.no/no/Found", response.TemplateName);

            Assert.AreEqual("google.no", response.DomainName.ToString());
            Assert.AreEqual("GOO371D-NORID", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2015, 01, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("GNA233O-NORID", response.Registrant.RegistryId);
            Assert.AreEqual("Google Norway AS", response.Registrant.Name);
            Assert.AreEqual("+47.23894000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+47.23894001", response.Registrant.FaxNumber);
            Assert.AreEqual("Dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Beddingen 10", response.Registrant.Address[0]);
            Assert.AreEqual("NO-7014", response.Registrant.Address[1]);
            Assert.AreEqual("Trondheim", response.Registrant.Address[2]);
            Assert.AreEqual("NO", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("RH3332P-NORID", response.AdminContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("MS5407P-NORID", response.TechnicalContact.RegistryId);


            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
