using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ec.Ex
{
    [TestFixture]
    public class ExParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.ec", "ex", "not_found.txt");
            var response = parser.Parse("whois.nic.ec", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ec/ex/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ec", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ec", "ex", "found.txt");
            var response = parser.Parse("whois.nic.ec", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ec/ex/Found", response.TemplateName);

            Assert.AreEqual("google.ec", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 09, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Registrant Details
            Assert.AreEqual("Rose Hagan", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("1-6503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("1-6503300100", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA 94043", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Domain Provisioning", response.AdminContact.Name);
            Assert.AreEqual("MarkMonitor", response.AdminContact.Organization);
            Assert.AreEqual("1208-3895799", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("10400 Overland Rd.,PMB 155", response.AdminContact.Address[0]);
            Assert.AreEqual("Boise, Idaho 83709", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(27, response.FieldsParsed);
        }
    }
}
