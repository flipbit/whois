using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dot.Cf.Cf
{
    [TestFixture]
    public class CfParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dot.cf", "cf", "found.txt");
            var response = parser.Parse("whois.dot.cf", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dot.cf/cf/Found", response.TemplateName);

            Assert.AreEqual("dot.cf", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 03, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Mr Joost  Zuurbier", response.Registrant.Name);
            Assert.AreEqual("Centrafrique TLD B.V.", response.Registrant.Organization);
            Assert.AreEqual("20-5315726", response.Registrant.TelephoneNumber);
            Assert.AreEqual("20-5315721", response.Registrant.FaxNumber);
            Assert.AreEqual("info@centrafriquetld.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Keizersgracht 213", response.Registrant.Address[0]);
            Assert.AreEqual("1016DT", response.Registrant.Address[1]);
            Assert.AreEqual("Amsterdam", response.Registrant.Address[2]);
            Assert.AreEqual("Noord-Holland", response.Registrant.Address[3]);
            Assert.AreEqual("Netherlands", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("Mr Joost  Zuurbier", response.AdminContact.Name);
            Assert.AreEqual("Centrafrique TLD B.V.", response.AdminContact.Organization);
            Assert.AreEqual("20-5315726", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("20-5315721", response.AdminContact.FaxNumber);
            Assert.AreEqual("info@centrafriquetld.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Keizersgracht 213", response.AdminContact.Address[0]);
            Assert.AreEqual("1016DT", response.AdminContact.Address[1]);
            Assert.AreEqual("Amsterdam", response.AdminContact.Address[2]);
            Assert.AreEqual("Noord-Holland", response.AdminContact.Address[3]);
            Assert.AreEqual("Netherlands", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("Mr Joost  Zuurbier", response.BillingContact.Name);
            Assert.AreEqual("Centrafrique TLD B.V.", response.BillingContact.Organization);
            Assert.AreEqual("20-5315726", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("20-5315721", response.BillingContact.FaxNumber);
            Assert.AreEqual("info@centrafriquetld.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Keizersgracht 213", response.BillingContact.Address[0]);
            Assert.AreEqual("1016DT", response.BillingContact.Address[1]);
            Assert.AreEqual("Amsterdam", response.BillingContact.Address[2]);
            Assert.AreEqual("Noord-Holland", response.BillingContact.Address[3]);
            Assert.AreEqual("Netherlands", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("Mr Joost  Zuurbier", response.TechnicalContact.Name);
            Assert.AreEqual("Centrafrique TLD B.V.", response.TechnicalContact.Organization);
            Assert.AreEqual("20-5315726", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("20-5315721", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("info@centrafriquetld.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Keizersgracht 213", response.TechnicalContact.Address[0]);
            Assert.AreEqual("1016DT", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Amsterdam", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Noord-Holland", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Netherlands", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("dns5.nettica.com", response.NameServers[0]);
            Assert.AreEqual("dns1.nettica.com", response.NameServers[1]);
            Assert.AreEqual("dns2.nettica.com", response.NameServers[2]);
            Assert.AreEqual("dns3.nettica.com", response.NameServers[3]);
            Assert.AreEqual("dns4.nettica.com", response.NameServers[4]);

            Assert.AreEqual(48, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dot.cf", "cf", "not_found.txt");
            var response = parser.Parse("whois.dot.cf", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dot.cf/cf/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dot.cf", "cf", "found_status_registered.txt");
            var response = parser.Parse("whois.dot.cf", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dot.cf/cf/Found", response.TemplateName);

            Assert.AreEqual("dot.cf", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 03, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Mr Joost  Zuurbier", response.Registrant.Name);
            Assert.AreEqual("Centrafrique TLD B.V.", response.Registrant.Organization);
            Assert.AreEqual("20-5315726", response.Registrant.TelephoneNumber);
            Assert.AreEqual("20-5315721", response.Registrant.FaxNumber);
            Assert.AreEqual("info@centrafriquetld.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Keizersgracht 213", response.Registrant.Address[0]);
            Assert.AreEqual("1016DT", response.Registrant.Address[1]);
            Assert.AreEqual("Amsterdam", response.Registrant.Address[2]);
            Assert.AreEqual("Noord-Holland", response.Registrant.Address[3]);
            Assert.AreEqual("Netherlands", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("Mr Joost  Zuurbier", response.AdminContact.Name);
            Assert.AreEqual("Centrafrique TLD B.V.", response.AdminContact.Organization);
            Assert.AreEqual("20-5315726", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("20-5315721", response.AdminContact.FaxNumber);
            Assert.AreEqual("info@centrafriquetld.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Keizersgracht 213", response.AdminContact.Address[0]);
            Assert.AreEqual("1016DT", response.AdminContact.Address[1]);
            Assert.AreEqual("Amsterdam", response.AdminContact.Address[2]);
            Assert.AreEqual("Noord-Holland", response.AdminContact.Address[3]);
            Assert.AreEqual("Netherlands", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("Mr Joost  Zuurbier", response.BillingContact.Name);
            Assert.AreEqual("Centrafrique TLD B.V.", response.BillingContact.Organization);
            Assert.AreEqual("20-5315726", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("20-5315721", response.BillingContact.FaxNumber);
            Assert.AreEqual("info@centrafriquetld.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Keizersgracht 213", response.BillingContact.Address[0]);
            Assert.AreEqual("1016DT", response.BillingContact.Address[1]);
            Assert.AreEqual("Amsterdam", response.BillingContact.Address[2]);
            Assert.AreEqual("Noord-Holland", response.BillingContact.Address[3]);
            Assert.AreEqual("Netherlands", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("Mr Joost  Zuurbier", response.TechnicalContact.Name);
            Assert.AreEqual("Centrafrique TLD B.V.", response.TechnicalContact.Organization);
            Assert.AreEqual("20-5315726", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("20-5315721", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("info@centrafriquetld.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Keizersgracht 213", response.TechnicalContact.Address[0]);
            Assert.AreEqual("1016DT", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Amsterdam", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Noord-Holland", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Netherlands", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("dns5.nettica.com", response.NameServers[0]);
            Assert.AreEqual("dns1.nettica.com", response.NameServers[1]);
            Assert.AreEqual("dns2.nettica.com", response.NameServers[2]);
            Assert.AreEqual("dns3.nettica.com", response.NameServers[3]);
            Assert.AreEqual("dns4.nettica.com", response.NameServers[4]);

            Assert.AreEqual(48, response.FieldsParsed);
        }
    }
}
