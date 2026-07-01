using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dk.Hostmaster.Dk.Dk
{
    [TestFixture]
    public class DkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_deactivated()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "deactivated.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Deactivated, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dk-hostmaster.dk/dk/Found", response.TemplateName);

            Assert.AreEqual("progolftours.dk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 08, 16, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 08, 31, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("LI1233-DK", response.Registrant.RegistryId);
            Assert.AreEqual("LH Invest", response.Registrant.Name);
            Assert.AreEqual("+4520645320", response.Registrant.TelephoneNumber);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Hausergade 36 1th", response.Registrant.Address[0]);
            Assert.AreEqual("1128", response.Registrant.Address[1]);
            Assert.AreEqual("København K", response.Registrant.Address[2]);
            Assert.AreEqual("DK", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("LI1233-DK", response.AdminContact.RegistryId);
            Assert.AreEqual("LH Invest", response.AdminContact.Name);
            Assert.AreEqual("+4520645320", response.AdminContact.TelephoneNumber);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Hausergade 36 1th", response.AdminContact.Address[0]);
            Assert.AreEqual("1128", response.AdminContact.Address[1]);
            Assert.AreEqual("København K", response.AdminContact.Address[2]);
            Assert.AreEqual("DK", response.AdminContact.Address[3]);


            // Nameservers
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("ns1.gratisdns.dk", response.NameServers[0]);
            Assert.AreEqual("ns2.gratisdns.dk", response.NameServers[1]);
            Assert.AreEqual("ns3.gratisdns.dk", response.NameServers[2]);
            Assert.AreEqual("ns4.gratisdns.dk", response.NameServers[3]);
            Assert.AreEqual("ns5.gratisdns.dk", response.NameServers[4]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Deactivated", response.DomainStatus[0]);

            Assert.AreEqual(24, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "reserved.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dk-hostmaster.dk/dk/Found", response.TemplateName);

            Assert.AreEqual("googlle.dk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 10, 24, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 10, 31, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Reserved", response.DomainStatus[0]);

            Assert.AreEqual(5, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "throttled.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dk-hostmaster.dk/dk/Throttled1", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled_response_throttled()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "throttled_response_throttled.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dk-hostmaster.dk/dk/Throttled2", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "not_found.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dk-hostmaster.dk/dk/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "found.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dk-hostmaster.dk/dk/Found", response.TemplateName);

            Assert.AreEqual("google.dk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(1999, 01, 10, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 03, 31, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GI656-DK", response.Registrant.RegistryId);
            Assert.AreEqual("Google, Inc", response.Registrant.Name);
            Assert.AreEqual("+16502530000", response.Registrant.TelephoneNumber);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("94043", response.Registrant.Address[1]);
            Assert.AreEqual("Mountain View, CA", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("GI657-DK", response.AdminContact.RegistryId);
            Assert.AreEqual("Google, Inc", response.AdminContact.Name);
            Assert.AreEqual("+16502530000", response.AdminContact.TelephoneNumber);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("94043", response.AdminContact.Address[1]);
            Assert.AreEqual("Mountain View, CA", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(21, response.FieldsParsed);
        }
    }
}
