using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Hm.Hm
{
    [TestFixture]
    public class HmParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.registry.hm", "hm", "not_found.txt");
            var response = parser.Parse("whois.registry.hm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound003", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registry.hm", "hm", "found.txt");
            var response = parser.Parse("whois.registry.hm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registry.hm/hm/Found", response.TemplateName);

            Assert.AreEqual("google.hm", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("HM Domain Registry", response.Registrar.Name);
            Assert.AreEqual("http://www.registry.hm/", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2003, 04, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 04, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("John G Rose", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1058 Jasmine St.", response.Registrant.Address[0]);
            Assert.AreEqual("Denver CO 80220", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("ROS00074", response.AdminContact.RegistryId);
            Assert.AreEqual("John Rose", response.AdminContact.Name);
            Assert.AreEqual("Sigma Polyplexic", response.AdminContact.Organization);
            Assert.AreEqual("2129996566", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("johnrose@polyplexic.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("1058 Jasmine St.", response.AdminContact.Address[0]);
            Assert.AreEqual("Denver CO 80220", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("ROS00074", response.BillingContact.RegistryId);
            Assert.AreEqual("John Rose", response.BillingContact.Name);
            Assert.AreEqual("Sigma Polyplexic", response.BillingContact.Organization);
            Assert.AreEqual("2129996566", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("johnrose@polyplexic.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("1058 Jasmine St.", response.BillingContact.Address[0]);
            Assert.AreEqual("Denver CO 80220", response.BillingContact.Address[1]);
            Assert.AreEqual("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("ROS00074", response.TechnicalContact.RegistryId);
            Assert.AreEqual("John Rose", response.TechnicalContact.Name);
            Assert.AreEqual("Sigma Polyplexic", response.TechnicalContact.Organization);
            Assert.AreEqual("2129996566", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("johnrose@polyplexic.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1058 Jasmine St.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Denver CO 80220", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.everydns.net", response.NameServers[0]);
            Assert.AreEqual("ns2.everydns.net", response.NameServers[1]);

            Assert.AreEqual(36, response.FieldsParsed);
        }
    }
}
