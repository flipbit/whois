using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Hkirc.Hk.Hk
{
    [TestFixture]
    public class HkParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.hkirc.hk", "hk", "found.txt");
            var response = parser.Parse("whois.hkirc.hk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.hkirc.hk/hk/Found", response.TemplateName);

            Assert.AreEqual("brighter.com.hk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Hong Kong Domain Name Registration Company Limited", response.Registrar.Name);
            Assert.AreEqual("enquiry@hkdnr.hk", response.Registrar.AbuseEmail);
            Assert.AreEqual("+852 2319 1313", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(1998, 12, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("THE BRIGHTER CO", response.Registrant.Name);
            Assert.AreEqual("qhau@neotech-hk.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("FLAT F-H,14/F,WINNER INDUSTRIAL BLDG.,", response.Registrant.Address[0]);
            Assert.AreEqual("HK", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.AreEqual("HK2763316T", response.AdminContact.RegistryId);
            Assert.AreEqual("THE BRIGHTER COMPANY", response.AdminContact.Organization);
            Assert.AreEqual("+852-23426328", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+852-23428180", response.AdminContact.FaxNumber);
            Assert.AreEqual("qhau@neotech-hk.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("FLAT F-H,14/F,WINNER INDUSTRIAL BLDG.,55 HUNG TO ROAD,KWUN TONG, KOWLOON", response.AdminContact.Address[0]);
            Assert.AreEqual("HK", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("HAU", response.TechnicalContact.Name);
            Assert.AreEqual("THE BRIGHTER COMPANY", response.TechnicalContact.Organization);
            Assert.AreEqual("+852-23426328", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+852-23428180", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("qhau@neotech-hk.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("FLAT F-H,14/F,WINNER INDUSTRIAL BLDG.,", response.TechnicalContact.Address[0]);
            Assert.AreEqual("HK", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns5.hostingspeed.net", response.NameServers[0]);
            Assert.AreEqual("ns2.hostingspeed.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Complete", response.DomainStatus[0]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.hkirc.hk", "hk", "not_found.txt");
            var response = parser.Parse("whois.hkirc.hk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.hkirc.hk/hk/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.hkirc.hk", "hk", "found_status_registered.txt");
            var response = parser.Parse("whois.hkirc.hk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.hkirc.hk/hk/Found", response.TemplateName);

            Assert.AreEqual("google.hk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MARKMONITOR INC.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2004, 04, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 03, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GOOGLE INC.", response.Registrant.Name);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("1600 AMPHITHEATRE PARKWAY   94043", response.Registrant.Address[0]);
            Assert.AreEqual("US", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.AreEqual("HK3602487T", response.AdminContact.RegistryId);
            Assert.AreEqual("GOOGLE INC.", response.AdminContact.Organization);
            Assert.AreEqual("+1-6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1-6502530001", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 AMPHITHEATRE PARKWAY   94043", response.AdminContact.Address[0]);
            Assert.AreEqual("US", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("ADMIN", response.TechnicalContact.Name);
            Assert.AreEqual("GOOGLE INC.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1-6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1-6502530001", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 AMPHITHEATRE PARKWAY   94043", response.TechnicalContact.Address[0]);
            Assert.AreEqual("US", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Complete", response.DomainStatus[0]);

            Assert.AreEqual(28, response.FieldsParsed);
        }
    }
}
