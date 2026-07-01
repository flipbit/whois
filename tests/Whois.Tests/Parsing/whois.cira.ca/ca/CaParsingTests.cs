using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cira.Ca.Ca
{
    [TestFixture]
    public class CaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cira.ca", "ca", "found.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/Found", response.TemplateName);

            Assert.AreEqual("glu.ca", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Webnames.ca Inc.", response.Registrar.Name);
            Assert.AreEqual("70", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2010, 12, 04, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 10, 30, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 10, 29, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Sanamato Inc.", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("Ross Vito", response.AdminContact.Name);
            Assert.AreEqual("1 (647) 964-4544", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("mail@sanamato.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("405 Queen Street South, P.O. Box 75004", response.AdminContact.Address[0]);
            Assert.AreEqual("Bolton ON L7E2B5 Canada", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("Ross Vito", response.TechnicalContact.Name);
            Assert.AreEqual("1 (647) 964-4544", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("mail@sanamato.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("405 Queen Street South, P.O. Box 75004", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Bolton ON L7E2B5 Canada", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.webnames.ca", response.NameServers[0]);
            Assert.AreEqual("ns2.webnames.ca", response.NameServers[1]);
            Assert.AreEqual("ns3.webnames.ca", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("registered", response.DomainStatus[0]);

            Assert.AreEqual(22, response.FieldsParsed);
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "not_assigned.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotAssigned, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/Found", response.TemplateName);

            Assert.AreEqual("abbylane.pe.ca", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("easyDNS Technologies Inc.", response.Registrar.Name);
            Assert.AreEqual("88", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2000, 10, 26, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 11, 30, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Abbylane Summer Homes", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("Jeff Carmody", response.AdminContact.Name);
            Assert.AreEqual("+1 902-621-0244", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1 902-566-0823", response.AdminContact.FaxNumber);
            Assert.AreEqual("jeff@abbylane.pe.ca", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Abbylane Summer Homes", response.AdminContact.Address[0]);
            Assert.AreEqual("8 Birchill Drive", response.AdminContact.Address[1]);
            Assert.AreEqual("Ch-town PE C1A 6W5 Canada", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("Jeff Carmody", response.TechnicalContact.Name);
            Assert.AreEqual("+1 902 566 0829", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1 902-628-4355", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("jeff@abbylane.pe.ca", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("550 University Ave", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Charlottetown PE C1A4p3 Canada", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns1.easydns.com", response.NameServers[0]);
            Assert.AreEqual("ns2.easydns.com", response.NameServers[1]);
            Assert.AreEqual("ns3.easydns.org", response.NameServers[2]);
            Assert.AreEqual("ns6.easydns.net", response.NameServers[3]);
            Assert.AreEqual("remote1.easydns.com", response.NameServers[4]);
            Assert.AreEqual("remote2.easydns.com", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("auto-renew grace", response.DomainStatus[0]);

            Assert.AreEqual(27, response.FieldsParsed);

            AssertWriter.Write(response);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "not_found.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ca", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("available", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "pending_delete.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/Found", response.TemplateName);

            Assert.AreEqual("sagespa.ca", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Go Daddy Domains Canada, Inc", response.Registrar.Name);
            Assert.AreEqual("2316042", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2013, 07, 31, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 05, 12, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 05, 12, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns75.domaincontrol.com", response.NameServers[0]);
            Assert.AreEqual("ns76.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pending delete", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }

        [Test]
        public void Test_redemption()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "redemption.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Redemption, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/Found", response.TemplateName);

            Assert.AreEqual("glu.ca", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Webnames.ca Inc.", response.Registrar.Name);
            Assert.AreEqual("70", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2010, 12, 04, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 10, 30, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 10, 29, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Sanamato Inc.", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("Ross Vito", response.AdminContact.Name);
            Assert.AreEqual("1 (647) 964-4544", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("mail@sanamato.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("405 Queen Street South, P.O. Box 75004", response.AdminContact.Address[0]);
            Assert.AreEqual("Bolton ON L7E2B5 Canada", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("Ross Vito", response.TechnicalContact.Name);
            Assert.AreEqual("1 (647) 964-4544", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("mail@sanamato.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("405 Queen Street South, P.O. Box 75004", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Bolton ON L7E2B5 Canada", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.webnames.ca", response.NameServers[0]);
            Assert.AreEqual("ns2.webnames.ca", response.NameServers[1]);
            Assert.AreEqual("ns3.webnames.ca", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("redemption", response.DomainStatus[0]);

            Assert.AreEqual(22, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered_2()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "found_status_registered_2.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/Found", response.TemplateName);

            Assert.AreEqual("google.ca", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Webnames.ca Inc.", response.Registrar.Name);
            Assert.AreEqual("70", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2000, 10, 03, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 04, 28, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("Rose Hagan", response.AdminContact.Name);
            Assert.AreEqual("1 416 8653361", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("1 416 9456616", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("130 King St. W., Suite 1800", response.AdminContact.Address[0]);
            Assert.AreEqual("Toronto ON M5X 1E3 Canada", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("Matt Serlin", response.TechnicalContact.Name);
            Assert.AreEqual("1.2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("1.2083895771", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Domain Provisioning,10400 Overland Rd. PMB 155", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Boise ID 83709 United States", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("registered", response.DomainStatus[0]);

            Assert.AreEqual(24, response.FieldsParsed);
        }

        [Test]
        public void Test_to_be_released()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "to_be_released.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.ToBeReleased, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/ToBeReleased", response.TemplateName);

            Assert.AreEqual("thomascraft.ca", response.DomainName.ToString());


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("to be released", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "unavailable.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/Unavailable", response.TemplateName);

            Assert.AreEqual("mediom.ca", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "not_found_status_available.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ca", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("available", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "invalid.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/Unavailable", response.TemplateName);

            Assert.AreEqual("mediom.ca", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "found_status_registered.txt");
            var response = parser.Parse("whois.cira.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cira.ca/ca/Found", response.TemplateName);

            Assert.AreEqual("google.ca", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor International Canada Ltd.", response.Registrar.Name);
            Assert.AreEqual("5000040", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2014, 02, 13, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 10, 03, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 04, 28, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("Christina Chiou", response.AdminContact.Name);
            Assert.AreEqual("+1.4168653361", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.4169456616", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("130 King St. W., Suite 1800,", response.AdminContact.Address[0]);
            Assert.AreEqual("Toronto ON M5X1E3 Canada", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("Matt Serlin", response.TechnicalContact.Name);
            Assert.AreEqual("+1.2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Domain Provisioning,10400 Overland Rd. PMB 155", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Boise ID 83709 United States", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("registered", response.DomainStatus[0]);

            Assert.AreEqual(25, response.FieldsParsed);
        }
    }
}
