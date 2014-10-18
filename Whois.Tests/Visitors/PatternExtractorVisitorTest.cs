using System.IO;
using NUnit.Framework;
using Whois.Domain;

namespace Whois.Visitors
{
    [TestFixture]
    public class PatternExtractorVisitorTest
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void TestParseRecord()
        {
            var sample = File.ReadAllText("..\\..\\Samples\\adobe.com.txt");

            var record = new WhoisRecord(sample);

            record = visitor.Visit(record);

            Assert.IsNotNull(record.Registrant);
            Assert.AreEqual("Domain Administrator", record.Registrant.Name);
            Assert.AreEqual("Adobe Systems Incorporated", record.Registrant.Organization);
            Assert.AreEqual("345 Park Avenue", record.Registrant.Street);
            Assert.AreEqual("San Jose", record.Registrant.City);
            Assert.AreEqual("CA", record.Registrant.State);
            Assert.AreEqual("95110", record.Registrant.PostalCode);
            Assert.AreEqual("US", record.Registrant.Country);
            Assert.AreEqual("+1.4085366000", record.Registrant.PhoneNumber);
            Assert.AreEqual("100", record.Registrant.PhoneNumberExt);
            Assert.AreEqual("123456", record.Registrant.FaxNumber);
            Assert.AreEqual("200", record.Registrant.FaxNumberExt);
            Assert.AreEqual("dns-admin@adobe.com", record.Registrant.Email);

            Assert.IsNotNull(record.AdminContact);
            Assert.AreEqual("DNS Admin", record.AdminContact.Name);
            Assert.AreEqual("Adobe Systems Incorporated", record.AdminContact.Organization);
            Assert.AreEqual("345 Park Avenue", record.AdminContact.Street);
            Assert.AreEqual("San Jose", record.AdminContact.City);
            Assert.AreEqual("CA", record.AdminContact.State);
            Assert.AreEqual("95110", record.AdminContact.PostalCode);
            Assert.AreEqual("US", record.AdminContact.Country);
            Assert.AreEqual("+1.4085366000", record.AdminContact.PhoneNumber);
            Assert.AreEqual(null, record.AdminContact.PhoneNumberExt);
            Assert.AreEqual(null, record.AdminContact.FaxNumber);
            Assert.AreEqual(null, record.AdminContact.FaxNumberExt);
            Assert.AreEqual("dns-admin@adobe.com", record.AdminContact.Email);

            Assert.IsNotNull(record.TechnicalContact);
            Assert.AreEqual("DNS Tech", record.TechnicalContact.Name);
            Assert.AreEqual("Adobe Systems Incorporated", record.TechnicalContact.Organization);
            Assert.AreEqual("345 Park Avenue", record.TechnicalContact.Street);
            Assert.AreEqual("San Jose", record.TechnicalContact.City);
            Assert.AreEqual("CA", record.TechnicalContact.State);
            Assert.AreEqual("95110", record.TechnicalContact.PostalCode);
            Assert.AreEqual("US", record.TechnicalContact.Country);
            Assert.AreEqual("+1.4085366000", record.TechnicalContact.PhoneNumber);
            Assert.AreEqual(null, record.TechnicalContact.PhoneNumberExt);
            Assert.AreEqual(null, record.TechnicalContact.FaxNumber);
            Assert.AreEqual(null, record.TechnicalContact.FaxNumberExt);
            Assert.AreEqual("dns-tech@adobe.com", record.TechnicalContact.Email);

            Assert.AreEqual(5, record.Nameservers.Count);
            Assert.AreEqual("adobe-dns-03.adobe.com", record.Nameservers[0]);
            Assert.AreEqual("adobe-dns-01.adobe.com", record.Nameservers[1]);
            Assert.AreEqual("adobe-dns-02.adobe.com", record.Nameservers[2]);
            Assert.AreEqual("adobe-dns-05.adobe.com", record.Nameservers[3]);
            Assert.AreEqual("adobe-dns-04.adobe.com", record.Nameservers[4]);
        }
    }
}
