using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Uk.Uk
{
    [TestFixture]
    public class UkParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("netbenefit.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Ascio Technologies Inc t/a Ascio Technologies inc [Tag = ASCIO]", response.Registrar.Name);
            Assert.AreEqual("http://www.ascio.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2011, 07, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 08, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Netbenefit (UK) Ltd", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("3rd Floor Prospero House", response.Registrant.Address[0]);
            Assert.AreEqual("241 Borough High Street", response.Registrant.Address[1]);
            Assert.AreEqual("London", response.Registrant.Address[2]);
            Assert.AreEqual("SE1 1GB", response.Registrant.Address[3]);
            Assert.AreEqual("United Kingdom", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns0.netbenefit.co.uk", response.NameServers[0]);
            Assert.AreEqual("ns1.netbenefit.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered until expiry date.", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_found_registrant_type_individual()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_registrant_type_individual.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("bedandbreakfastsearcher.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Webfusion Ltd t/a 123-reg [Tag = 123-REG]", response.Registrar.Name);
            Assert.AreEqual("http://www.123-reg.co.uk", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2012, 04, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Mike Peacock", response.Registrant.Name);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.rapidswitch.com", response.NameServers[0]);
            Assert.AreEqual("ns2.rapidswitch.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered until expiry date.", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }

        [Test]
        public void Test_found_registrant_type_unknown()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_registrant_type_unknown.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("google.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Markmonitor Inc. t/a Markmonitor [Tag = MARKMONITOR]", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2011, 02, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("United States", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered until expiry date.", response.DomainStatus[0]);

            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_found_registrar_godaddy()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_registrar_godaddy.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("ecigsbrand.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("GoDaddy.com, LLP. [Tag = GODADDY]", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 09, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 09, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Vitality & Wellness Ltd.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("72 High Street", response.Registrant.Address[0]);
            Assert.AreEqual("Haslemere", response.Registrant.Address[1]);
            Assert.AreEqual("Surrey", response.Registrant.Address[2]);
            Assert.AreEqual("GU27 2LA", response.Registrant.Address[3]);
            Assert.AreEqual("United Kingdom", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("pdns01.domaincontrol.com", response.NameServers[0]);
            Assert.AreEqual("pdns02.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered until expiry date.", response.DomainStatus[0]);

            Assert.AreEqual(15, response.FieldsParsed);
        }

        [Test]
        public void Test_found_registrar_without_trading_name()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_registrar_without_trading_name.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("netbenefit.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NetNames Limited [Tag = NETNAMES]", response.Registrar.Name);
            Assert.AreEqual("http://www.netnames.co.uk", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2010, 07, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Netbenefit (UK) Ltd", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("3rd Floor Prospero House", response.Registrant.Address[0]);
            Assert.AreEqual("241 Borough High Street", response.Registrant.Address[1]);
            Assert.AreEqual("London", response.Registrant.Address[2]);
            Assert.AreEqual("SE1 1GB", response.Registrant.Address[3]);
            Assert.AreEqual("United Kingdom", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns0.netbenefit.co.uk", response.NameServers[0]);
            Assert.AreEqual("ns1.netbenefit.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered until renewal date.", response.DomainStatus[0]);

            Assert.AreEqual(15, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "not_found.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.co.uk", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_no_longer_required()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_no_longer_required.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("atlasholidays.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Print Copy Systems Limited t/a Lan Systems [Tag = LANSYSTEMS]", response.Registrar.Name);
            Assert.AreEqual("http://www.lansystems.co.uk", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 05, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Atlas Associates", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("The PC Clinic (UK) Ltd., 1 Hinckley Road,", response.Registrant.Address[0]);
            Assert.AreEqual("Sapcote", response.Registrant.Address[1]);
            Assert.AreEqual("Leicestershire", response.Registrant.Address[2]);
            Assert.AreEqual("LE9 4FS", response.Registrant.Address[3]);
            Assert.AreEqual("United Kingdom", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.thenameservers.co.uk", response.NameServers[0]);
            Assert.AreEqual("ns2.thenameservers.co.uk", response.NameServers[1]);
            Assert.AreEqual("ns3.thenameservers.co.uk", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("No longer required", response.DomainStatus[0]);

            Assert.AreEqual(17, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_no_status_listed()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_no_status_listed.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("internet.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("No registrar listed.  This domain is registered directly with Nominet.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 03, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Nominet UK", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Minerva House, Edmund Halley Road", response.Registrant.Address[0]);
            Assert.AreEqual("Oxford Science Park", response.Registrant.Address[1]);
            Assert.AreEqual("Oxford", response.Registrant.Address[2]);
            Assert.AreEqual("Oxon", response.Registrant.Address[3]);
            Assert.AreEqual("OX4 4DQ", response.Registrant.Address[4]);
            Assert.AreEqual("United Kingdom", response.Registrant.Address[5]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("nom-ns1.nominet.org.uk", response.NameServers[0]);
            Assert.AreEqual("nom-ns2.nominet.org.uk", response.NameServers[1]);
            Assert.AreEqual("nom-ns3.nominet.org.uk", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("No registration status listed.", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_processing_registration()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_processing_registration.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("reachingyoungmales.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Webfusion Ltd t/a 123-Reg.co.uk [Tag = 123-REG]", response.Registrar.Name);
            Assert.AreEqual("http://www.123-reg.co.uk", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2010, 09, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 09, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("VCCP digital", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Greencoat House", response.Registrant.Address[0]);
            Assert.AreEqual("Francis Street Victoria", response.Registrant.Address[1]);
            Assert.AreEqual("London", response.Registrant.Address[2]);
            Assert.AreEqual("London", response.Registrant.Address[3]);
            Assert.AreEqual("SW1P 1DH", response.Registrant.Address[4]);
            Assert.AreEqual("United Kingdom", response.Registrant.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns.123-reg.co.uk", response.NameServers[0]);
            Assert.AreEqual("ns2.123-reg.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registration request being processed.", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_processing_renewal()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_processing_renewal.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("creatinghomeowners.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Webfusion Ltd t/a 123-Reg.co.uk [Tag = 123-REG]", response.Registrar.Name);
            Assert.AreEqual("http://www.123-reg.co.uk", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2010, 09, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 09, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("VCCP digital", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Greencoat House", response.Registrant.Address[0]);
            Assert.AreEqual("Francis Street Victoria", response.Registrant.Address[1]);
            Assert.AreEqual("London", response.Registrant.Address[2]);
            Assert.AreEqual("London", response.Registrant.Address[3]);
            Assert.AreEqual("SW1P 1DH", response.Registrant.Address[4]);
            Assert.AreEqual("United Kingdom", response.Registrant.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns.123-reg.co.uk", response.NameServers[0]);
            Assert.AreEqual("ns2.123-reg.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Renewal request being processed.", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_registered_until_expiry_date()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_registered_until_expiry_date.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("google.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Markmonitor Inc. t/a Markmonitor [Tag = MARKMONITOR]", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2011, 02, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("United States", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered until expiry date.", response.DomainStatus[0]);

            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "suspended.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Suspended, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("allofshoes.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Key-Systems GmbH [Tag = KEY-SYSTEMS-DE]", response.Registrar.Name);
            Assert.AreEqual("http://www.key-systems.net", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2012, 02, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Yuan Chen", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Meiyuan Road", response.Registrant.Address[0]);
            Assert.AreEqual("Putian", response.Registrant.Address[1]);
            Assert.AreEqual("351100", response.Registrant.Address[2]);
            Assert.AreEqual("China", response.Registrant.Address[3]);


            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("Renewal required.", response.DomainStatus[0]);
            Assert.AreEqual("*** This registration has been SUSPENDED. ***", response.DomainStatus[1]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "throttled.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Throttled", response.TemplateName);

            Assert.AreEqual("google.co.uk", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.co.uk", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "invalid.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Invalid, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Invalid", response.TemplateName);

            Assert.AreEqual("u34jedzcq.uk", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("google.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Markmonitor Inc. t/a Markmonitor [Tag = MARKMONITOR]", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2014, 01, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("United States", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered until expiry date.", response.DomainStatus[0]);

            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "reserved.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("internet.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("No registrar listed.  This domain is registered directly with Nominet.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 03, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Nominet UK", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Minerva House, Edmund Halley Road", response.Registrant.Address[0]);
            Assert.AreEqual("Oxford Science Park", response.Registrant.Address[1]);
            Assert.AreEqual("Oxford", response.Registrant.Address[2]);
            Assert.AreEqual("Oxon", response.Registrant.Address[3]);
            Assert.AreEqual("OX4 4DQ", response.Registrant.Address[4]);
            Assert.AreEqual("United Kingdom", response.Registrant.Address[5]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("nom-ns1.nominet.org.uk", response.NameServers[0]);
            Assert.AreEqual("nom-ns2.nominet.org.uk", response.NameServers[1]);
            Assert.AreEqual("nom-ns3.nominet.org.uk", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("No registration status listed.", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_suspended_status_suspended()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "suspended_status_suspended.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.AreEqual(WhoisStatus.Suspended, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.uk/uk/Found", response.TemplateName);

            Assert.AreEqual("allofshoes.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Key-Systems GmbH [Tag = KEY-SYSTEMS-DE]", response.Registrar.Name);
            Assert.AreEqual("http://www.key-systems.net", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2012, 02, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Yuan Chen", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Meiyuan Road", response.Registrant.Address[0]);
            Assert.AreEqual("Putian", response.Registrant.Address[1]);
            Assert.AreEqual("351100", response.Registrant.Address[2]);
            Assert.AreEqual("China", response.Registrant.Address[3]);


            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("Renewal required.", response.DomainStatus[0]);
            Assert.AreEqual("*** This registration has been SUSPENDED. ***", response.DomainStatus[1]);

            Assert.AreEqual(14, response.FieldsParsed);
        }
    }
}
