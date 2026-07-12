using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Uk.Uk
{
    public class UkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public UkParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("netbenefit.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Ascio Technologies Inc t/a Ascio Technologies inc [Tag = ASCIO]", response.Registrar.Name);
            Assert.Equal("http://www.ascio.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2011, 07, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1996, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2012, 08, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Netbenefit (UK) Ltd", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("3rd Floor Prospero House", response.Registrant.Address[0]);
            Assert.Equal("241 Borough High Street", response.Registrant.Address[1]);
            Assert.Equal("London", response.Registrant.Address[2]);
            Assert.Equal("SE1 1GB", response.Registrant.Address[3]);
            Assert.Equal("United Kingdom", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns0.netbenefit.co.uk", response.NameServers[0]);
            Assert.Equal("ns1.netbenefit.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered until expiry date.", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_registrant_type_individual()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found_registrant_type_individual.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("bedandbreakfastsearcher.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Webfusion Ltd t/a 123-reg [Tag = 123-REG]", response.Registrar.Name);
            Assert.Equal("http://www.123-reg.co.uk", response.Registrar.Url);

            Assert.Equal(new DateTime(2012, 04, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Mike Peacock", response.Registrant.Name);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.rapidswitch.com", response.NameServers[0]);
            Assert.Equal("ns2.rapidswitch.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered until expiry date.", response.DomainStatus[0]);

            Assert.Equal(11, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_registrant_type_unknown()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found_registrant_type_unknown.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("google.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Markmonitor Inc. t/a Markmonitor [Tag = MARKMONITOR]", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2011, 02, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("United States", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered until expiry date.", response.DomainStatus[0]);

            Assert.Equal(18, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_registrar_godaddy()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found_registrar_godaddy.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("ecigsbrand.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("GoDaddy.com, LLP. [Tag = GODADDY]", response.Registrar.Name);

            Assert.Equal(new DateTime(2012, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 09, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 09, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Vitality & Wellness Ltd.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("72 High Street", response.Registrant.Address[0]);
            Assert.Equal("Haslemere", response.Registrant.Address[1]);
            Assert.Equal("Surrey", response.Registrant.Address[2]);
            Assert.Equal("GU27 2LA", response.Registrant.Address[3]);
            Assert.Equal("United Kingdom", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("pdns01.domaincontrol.com", response.NameServers[0]);
            Assert.Equal("pdns02.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered until expiry date.", response.DomainStatus[0]);

            Assert.Equal(15, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_registrar_without_trading_name()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found_registrar_without_trading_name.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("netbenefit.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("NetNames Limited [Tag = NETNAMES]", response.Registrar.Name);
            Assert.Equal("http://www.netnames.co.uk", response.Registrar.Url);

            Assert.Equal(new DateTime(2010, 07, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1996, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Netbenefit (UK) Ltd", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("3rd Floor Prospero House", response.Registrant.Address[0]);
            Assert.Equal("241 Borough High Street", response.Registrant.Address[1]);
            Assert.Equal("London", response.Registrant.Address[2]);
            Assert.Equal("SE1 1GB", response.Registrant.Address[3]);
            Assert.Equal("United Kingdom", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns0.netbenefit.co.uk", response.NameServers[0]);
            Assert.Equal("ns1.netbenefit.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered until renewal date.", response.DomainStatus[0]);

            Assert.Equal(15, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.co.uk", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_no_longer_required()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "other_status_no_longer_required.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("atlasholidays.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Print Copy Systems Limited t/a Lan Systems [Tag = LANSYSTEMS]", response.Registrar.Name);
            Assert.Equal("http://www.lansystems.co.uk", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 05, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Atlas Associates", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("The PC Clinic (UK) Ltd., 1 Hinckley Road,", response.Registrant.Address[0]);
            Assert.Equal("Sapcote", response.Registrant.Address[1]);
            Assert.Equal("Leicestershire", response.Registrant.Address[2]);
            Assert.Equal("LE9 4FS", response.Registrant.Address[3]);
            Assert.Equal("United Kingdom", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.thenameservers.co.uk", response.NameServers[0]);
            Assert.Equal("ns2.thenameservers.co.uk", response.NameServers[1]);
            Assert.Equal("ns3.thenameservers.co.uk", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("No longer required", response.DomainStatus[0]);

            Assert.Equal(17, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_no_status_listed()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "other_status_no_status_listed.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("internet.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("No registrar listed.  This domain is registered directly with Nominet.", response.Registrar.Name);

            Assert.Equal(new DateTime(2012, 03, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1996, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Nominet UK", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Minerva House, Edmund Halley Road", response.Registrant.Address[0]);
            Assert.Equal("Oxford Science Park", response.Registrant.Address[1]);
            Assert.Equal("Oxford", response.Registrant.Address[2]);
            Assert.Equal("Oxon", response.Registrant.Address[3]);
            Assert.Equal("OX4 4DQ", response.Registrant.Address[4]);
            Assert.Equal("United Kingdom", response.Registrant.Address[5]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("nom-ns1.nominet.org.uk", response.NameServers[0]);
            Assert.Equal("nom-ns2.nominet.org.uk", response.NameServers[1]);
            Assert.Equal("nom-ns3.nominet.org.uk", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("No registration status listed.", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_processing_registration()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "other_status_processing_registration.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("reachingyoungmales.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Webfusion Ltd t/a 123-Reg.co.uk [Tag = 123-REG]", response.Registrar.Name);
            Assert.Equal("http://www.123-reg.co.uk", response.Registrar.Url);

            Assert.Equal(new DateTime(2010, 09, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 09, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("VCCP digital", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Greencoat House", response.Registrant.Address[0]);
            Assert.Equal("Francis Street Victoria", response.Registrant.Address[1]);
            Assert.Equal("London", response.Registrant.Address[2]);
            Assert.Equal("London", response.Registrant.Address[3]);
            Assert.Equal("SW1P 1DH", response.Registrant.Address[4]);
            Assert.Equal("United Kingdom", response.Registrant.Address[5]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns.123-reg.co.uk", response.NameServers[0]);
            Assert.Equal("ns2.123-reg.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registration request being processed.", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_processing_renewal()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "other_status_processing_renewal.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("creatinghomeowners.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Webfusion Ltd t/a 123-Reg.co.uk [Tag = 123-REG]", response.Registrar.Name);
            Assert.Equal("http://www.123-reg.co.uk", response.Registrar.Url);

            Assert.Equal(new DateTime(2010, 09, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 09, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("VCCP digital", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Greencoat House", response.Registrant.Address[0]);
            Assert.Equal("Francis Street Victoria", response.Registrant.Address[1]);
            Assert.Equal("London", response.Registrant.Address[2]);
            Assert.Equal("London", response.Registrant.Address[3]);
            Assert.Equal("SW1P 1DH", response.Registrant.Address[4]);
            Assert.Equal("United Kingdom", response.Registrant.Address[5]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns.123-reg.co.uk", response.NameServers[0]);
            Assert.Equal("ns2.123-reg.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Renewal request being processed.", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_registered_until_expiry_date()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "other_status_registered_until_expiry_date.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("google.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Markmonitor Inc. t/a Markmonitor [Tag = MARKMONITOR]", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2011, 02, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("United States", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered until expiry date.", response.DomainStatus[0]);

            Assert.Equal(18, response.FieldsParsed);
        }

        [Fact]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "suspended", "suspended.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Suspended, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("allofshoes.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Key-Systems GmbH [Tag = KEY-SYSTEMS-DE]", response.Registrar.Name);
            Assert.Equal("http://www.key-systems.net", response.Registrar.Url);

            Assert.Equal(new DateTime(2012, 02, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Yuan Chen", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Meiyuan Road", response.Registrant.Address[0]);
            Assert.Equal("Putian", response.Registrant.Address[1]);
            Assert.Equal("351100", response.Registrant.Address[2]);
            Assert.Equal("China", response.Registrant.Address[3]);


            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("Renewal required.", response.DomainStatus[0]);
            Assert.Equal("*** This registration has been SUSPENDED. ***", response.DomainStatus[1]);

            Assert.Equal(14, response.FieldsParsed);
        }

        [Fact]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "throttled", "throttled.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Throttled, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/throttled/01", response.TemplateName);

            Assert.Equal("google-throttled.co.uk", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "not-found", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.co.uk", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "invalid", "invalid.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Invalid, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/invalid/01", response.TemplateName);

            Assert.Equal("u34jedzcq.uk", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("google.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Markmonitor Inc. t/a Markmonitor [Tag = MARKMONITOR]", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2014, 01, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("United States", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered until expiry date.", response.DomainStatus[0]);

            Assert.Equal(18, response.FieldsParsed);
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "reserved", "reserved.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("internet-reserved.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("No registrar listed.  This domain is registered directly with Nominet.", response.Registrar.Name);

            Assert.Equal(new DateTime(2012, 03, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1996, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Nominet UK", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Minerva House, Edmund Halley Road", response.Registrant.Address[0]);
            Assert.Equal("Oxford Science Park", response.Registrant.Address[1]);
            Assert.Equal("Oxford", response.Registrant.Address[2]);
            Assert.Equal("Oxon", response.Registrant.Address[3]);
            Assert.Equal("OX4 4DQ", response.Registrant.Address[4]);
            Assert.Equal("United Kingdom", response.Registrant.Address[5]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("nom-ns1.nominet.org.uk", response.NameServers[0]);
            Assert.Equal("nom-ns2.nominet.org.uk", response.NameServers[1]);
            Assert.Equal("nom-ns3.nominet.org.uk", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("No registration status listed.", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_suspended_status_suspended()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "suspended", "suspended_status_suspended.txt");
            var response = parser.Parse("whois.nic.uk", sample);

            Assert.Equal(WhoisStatus.Suspended, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.uk/uk/found/01", response.TemplateName);

            Assert.Equal("allofshoes.co.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Key-Systems GmbH [Tag = KEY-SYSTEMS-DE]", response.Registrar.Name);
            Assert.Equal("http://www.key-systems.net", response.Registrar.Url);

            Assert.Equal(new DateTime(2012, 02, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 08, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Yuan Chen", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Meiyuan Road", response.Registrant.Address[0]);
            Assert.Equal("Putian", response.Registrant.Address[1]);
            Assert.Equal("351100", response.Registrant.Address[2]);
            Assert.Equal("China", response.Registrant.Address[3]);


            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("Renewal required.", response.DomainStatus[0]);
            Assert.Equal("*** This registration has been SUSPENDED. ***", response.DomainStatus[1]);

            Assert.Equal(14, response.FieldsParsed);
        }
    }
}
