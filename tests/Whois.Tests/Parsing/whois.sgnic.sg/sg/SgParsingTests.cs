using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sgnic.Sg.Sg
{
    [TestFixture]
    public class SgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found.txt");
            var response = parser.Parse("whois.sgnic.sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sgnic.sg/sg/Found01", response.TemplateName);

            Assert.AreEqual("google.sg", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MARKMONITOR INC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2005, 01, 03, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 01, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GOOGLE INC.", response.Registrant.Name);
            Assert.AreEqual("+1.6503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506181434", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 AMPHITHEATRE PARKWAY", response.Registrant.Address[0]);
            Assert.AreEqual("CA", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);


            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[2]);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[3]);

            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_schema_1_with_ip()
        {
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found_nameservers_schema_1_with_ip.txt");
            var response = parser.Parse("whois.sgnic.sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sgnic.sg/sg/Found01", response.TemplateName);

            Assert.AreEqual("canon.com.sg", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("SINGNET PTE LTD", response.Registrar.Name);

            Assert.AreEqual(new DateTime(1996, 01, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 01, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("CANON SINGAPORE PTE. LTD.", response.Registrant.Name);
            Assert.AreEqual("67845922", response.Registrant.TelephoneNumber);
            Assert.AreEqual("64753273", response.Registrant.FaxNumber);
            Assert.AreEqual("hostmaster@singnet.com.sg", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1 HarbourFront Avenue", response.Registrant.Address[0]);
            Assert.AreEqual("SG", response.Registrant.Address[1]);
            Assert.AreEqual("098632", response.Registrant.Address[2]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_schema_2()
        {
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found_nameservers_schema_2.txt");
            var response = parser.Parse("whois.sgnic.sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sgnic.sg/sg/Found01", response.TemplateName);

            Assert.AreEqual("google.sg", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MARKMONITOR INC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2005, 01, 03, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 01, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GOOGLE INC.", response.Registrant.Name);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 AMPHITHEATRE PARKWAY", response.Registrant.Address[0]);
            Assert.AreEqual("CA", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);


            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[2]);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[3]);

            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "not_found.txt");
            var response = parser.Parse("whois.sgnic.sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound002", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found_status_registered.txt");
            var response = parser.Parse("whois.sgnic.sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sgnic.sg/sg/Found02", response.TemplateName);

            Assert.AreEqual("google.sg", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MARKMONITOR INC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2005, 01, 03, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 01, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GOOGLE LLC", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("MARKMONITOR INC.", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.AreEqual("GOOGLE LLC", response.TechnicalContact.Name);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(5, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[2]);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[3]);
            Assert.AreEqual("VerifiedID@SG-Not Required", response.DomainStatus[4]);

            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
