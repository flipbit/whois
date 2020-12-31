using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Travel.Travel
{
    [TestFixture]
    public class TravelParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.travel", "travel", "found.txt");
            var response = parser.Parse("whois.nic.travel", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.travel/travel/Found", response.TemplateName);

            Assert.AreEqual("webcams.travel", response.DomainName.ToString());
            Assert.AreEqual("D108042-TRAVEL", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("111", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2012, 07, 31, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 08, 01, 12, 39, 21, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 08, 30, 12, 52, 13, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("P-IRO86-YIHZ", response.Registrant.RegistryId);
            Assert.AreEqual("Ingo Oppermann", response.Registrant.Name);
            Assert.AreEqual("OPAG Online Promotion AG", response.Registrant.Organization);
            Assert.AreEqual("+41.442777501", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+41.763770216", response.Registrant.FaxNumber);
            Assert.AreEqual("ingo.oppermann@topin.travel", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Austr.37", response.Registrant.Address[0]);
            Assert.AreEqual("Vaduz", response.Registrant.Address[1]);
            Assert.AreEqual("9490", response.Registrant.Address[2]);
            Assert.AreEqual("Liechtenstein", response.Registrant.Address[3]);
            Assert.AreEqual("LI", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("P-IRO86-YIHZ", response.AdminContact.RegistryId);
            Assert.AreEqual("Ingo Oppermann", response.AdminContact.Name);
            Assert.AreEqual("OPAG Online Promotion AG", response.AdminContact.Organization);
            Assert.AreEqual("+41.442777501", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+41.763770216", response.AdminContact.FaxNumber);
            Assert.AreEqual("ingo.oppermann@topin.travel", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Austr.37", response.AdminContact.Address[0]);
            Assert.AreEqual("Vaduz", response.AdminContact.Address[1]);
            Assert.AreEqual("9490", response.AdminContact.Address[2]);
            Assert.AreEqual("Liechtenstein", response.AdminContact.Address[3]);
            Assert.AreEqual("LI", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("P-HVO132-PVII", response.BillingContact.RegistryId);
            Assert.AreEqual("Hans-Peter Oswald", response.BillingContact.Name);
            Assert.AreEqual("Secura GmbH", response.BillingContact.Organization);
            Assert.AreEqual("+49.2212571213", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+49.221925227", response.BillingContact.FaxNumber);
            Assert.AreEqual("secura@domainregistry.de", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(6, response.BillingContact.Address.Count);
            Assert.AreEqual("Frohnhofweg 18", response.BillingContact.Address[0]);
            Assert.AreEqual("Koeln", response.BillingContact.Address[1]);
            Assert.AreEqual("NRW", response.BillingContact.Address[2]);
            Assert.AreEqual("50858", response.BillingContact.Address[3]);
            Assert.AreEqual("Germany", response.BillingContact.Address[4]);
            Assert.AreEqual("DE", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("P-HVO132-PVII", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Hans-Peter Oswald", response.TechnicalContact.Name);
            Assert.AreEqual("Secura GmbH", response.TechnicalContact.Organization);
            Assert.AreEqual("+49.2212571213", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+49.221925227", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("secura@domainregistry.de", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Frohnhofweg 18", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Koeln", response.TechnicalContact.Address[1]);
            Assert.AreEqual("NRW", response.TechnicalContact.Address[2]);
            Assert.AreEqual("50858", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Germany", response.TechnicalContact.Address[4]);
            Assert.AreEqual("DE", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("finkployd.nrg4u.com", response.NameServers[0]);
            Assert.AreEqual("c00l3r.networx.ch", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);

            Assert.AreEqual(57, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_single()
        {
            var sample = SampleReader.Read("whois.nic.travel", "travel", "other_status_single.txt");
            var response = parser.Parse("whois.nic.travel", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.travel/travel/Found", response.TemplateName);

            Assert.AreEqual("travel.travel", response.DomainName.ToString());
            Assert.AreEqual("D24096-TRAVEL", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2010, 10, 03, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 10, 04, 21, 44, 27, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2006, 07, 23, 16, 08, 37, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("TRALLIANCE", response.Registrant.RegistryId);
            Assert.AreEqual("Tralliance Corporation", response.Registrant.Name);
            Assert.AreEqual("+1.9547695999", response.Registrant.TelephoneNumber);
            Assert.AreEqual("info@tralliance.travel", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("110 East Broward Blvd, 14th floor", response.Registrant.Address[0]);
            Assert.AreEqual("Fort Lauderdale", response.Registrant.Address[1]);
            Assert.AreEqual("FL", response.Registrant.Address[2]);
            Assert.AreEqual("33301", response.Registrant.Address[3]);
            Assert.AreEqual("United States", response.Registrant.Address[4]);
            Assert.AreEqual("US", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.AreEqual("TRALLIANCE", response.AdminContact.RegistryId);
            Assert.AreEqual("Tralliance Corporation", response.AdminContact.Name);
            Assert.AreEqual("+1.9547695999", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("info@tralliance.travel", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("110 East Broward Blvd, 14th floor", response.AdminContact.Address[0]);
            Assert.AreEqual("Fort Lauderdale", response.AdminContact.Address[1]);
            Assert.AreEqual("FL", response.AdminContact.Address[2]);
            Assert.AreEqual("33301", response.AdminContact.Address[3]);
            Assert.AreEqual("United States", response.AdminContact.Address[4]);
            Assert.AreEqual("US", response.AdminContact.Address[5]);


             // BillingContact Details
            Assert.AreEqual("TRALLIANCE", response.BillingContact.RegistryId);
            Assert.AreEqual("Tralliance Corporation", response.BillingContact.Name);
            Assert.AreEqual("+1.9547695999", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("info@tralliance.travel", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(6, response.BillingContact.Address.Count);
            Assert.AreEqual("110 East Broward Blvd, 14th floor", response.BillingContact.Address[0]);
            Assert.AreEqual("Fort Lauderdale", response.BillingContact.Address[1]);
            Assert.AreEqual("FL", response.BillingContact.Address[2]);
            Assert.AreEqual("33301", response.BillingContact.Address[3]);
            Assert.AreEqual("United States", response.BillingContact.Address[4]);
            Assert.AreEqual("US", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("TRALLIANCE", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Tralliance Corporation", response.TechnicalContact.Name);
            Assert.AreEqual("+1.9547695999", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("info@tralliance.travel", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("110 East Broward Blvd, 14th floor", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Fort Lauderdale", response.TechnicalContact.Address[1]);
            Assert.AreEqual("FL", response.TechnicalContact.Address[2]);
            Assert.AreEqual("33301", response.TechnicalContact.Address[3]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[4]);
            Assert.AreEqual("US", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("netsys.com", response.NameServers[0]);
            Assert.AreEqual("ns01-mia.theglobe.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(49, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.travel", "travel", "not_found.txt");
            var response = parser.Parse("whois.nic.travel", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.travel/travel/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.travel", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.travel", "travel", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.travel", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.travel/travel/Found", response.TemplateName);

            Assert.AreEqual("travel.travel", response.DomainName.ToString());
            Assert.AreEqual("D24096-TRAVEL", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2021, 10, 03, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 10, 04, 21, 44, 27, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 09, 18, 15, 13, 32, 000, DateTimeKind.Utc), response.Expiration);

             // Registrar Details
            Assert.AreEqual("whois.neustar.us", response.Registrar.Url);

             // Registrant Details
            Assert.AreEqual("TRALLIANCE", response.Registrant.RegistryId);
            Assert.AreEqual("Tralliance Corporation", response.Registrant.Name);
            Assert.AreEqual("+1.9547695999", response.Registrant.TelephoneNumber);
            Assert.AreEqual("info@tralliance.travel", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("110 East Broward Blvd, 14th floor", response.Registrant.Address[0]);
            Assert.AreEqual("Fort Lauderdale", response.Registrant.Address[1]);
            Assert.AreEqual("FL", response.Registrant.Address[2]);
            Assert.AreEqual("33301", response.Registrant.Address[3]);
            Assert.AreEqual("United States", response.Registrant.Address[4]);
            Assert.AreEqual("US", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.AreEqual("TRALLIANCE", response.AdminContact.RegistryId);
            Assert.AreEqual("Tralliance Corporation", response.AdminContact.Name);
            Assert.AreEqual("+1.9547695999", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("info@tralliance.travel", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("110 East Broward Blvd, 14th floor", response.AdminContact.Address[0]);
            Assert.AreEqual("Fort Lauderdale", response.AdminContact.Address[1]);
            Assert.AreEqual("FL", response.AdminContact.Address[2]);
            Assert.AreEqual("33301", response.AdminContact.Address[3]);
            Assert.AreEqual("United States", response.AdminContact.Address[4]);
            Assert.AreEqual("US", response.AdminContact.Address[5]);


             // BillingContact Details
            Assert.AreEqual("TRALLIANCE", response.BillingContact.RegistryId);
            Assert.AreEqual("Tralliance Corporation", response.BillingContact.Name);
            Assert.AreEqual("+1.9547695999", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("info@tralliance.travel", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(6, response.BillingContact.Address.Count);
            Assert.AreEqual("110 East Broward Blvd, 14th floor", response.BillingContact.Address[0]);
            Assert.AreEqual("Fort Lauderdale", response.BillingContact.Address[1]);
            Assert.AreEqual("FL", response.BillingContact.Address[2]);
            Assert.AreEqual("33301", response.BillingContact.Address[3]);
            Assert.AreEqual("United States", response.BillingContact.Address[4]);
            Assert.AreEqual("US", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("TRALLIANCE", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Tralliance Corporation", response.TechnicalContact.Name);
            Assert.AreEqual("+1.9547695999", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("info@tralliance.travel", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("110 East Broward Blvd, 14th floor", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Fort Lauderdale", response.TechnicalContact.Address[1]);
            Assert.AreEqual("FL", response.TechnicalContact.Address[2]);
            Assert.AreEqual("33301", response.TechnicalContact.Address[3]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[4]);
            Assert.AreEqual("US", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns01-mia.theglobe.com", response.NameServers[0]);
            Assert.AreEqual("netsys.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(50, response.FieldsParsed);
        }
    }
}
