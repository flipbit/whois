using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Srs.Net.Nz.Nz
{
    [TestFixture]
    public class NzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_pendingrelease()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "other_status_pendingrelease.txt");
            var response = parser.Parse("whois.srs.net.nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.srs.net.nz/nz/Found", response.TemplateName);

            Assert.AreEqual("zumbafitness.co.nz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NETREGISTRY PTY LTD", response.Registrar.Name);
            Assert.AreEqual("dnsadmin@netregistry.com.au", response.Registrar.AbuseEmail);
            Assert.AreEqual("+61 2 9699 6099", response.Registrar.AbuseTelephoneNumber);


             // Registrant Details
            Assert.AreEqual("Zumba Fitness, Rodrigo, Faerman", response.Registrant.Name);
            Assert.AreEqual("+1 9 549253755", response.Registrant.TelephoneNumber);
            Assert.AreEqual("rodrigo@zumba.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("3801 North 29th Avenue", response.Registrant.Address[0]);
            Assert.AreEqual("Hollywood", response.Registrant.Address[1]);
            Assert.AreEqual("GB (UNITED KINGDOM)", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("NetRegistry", response.AdminContact.Name);
            Assert.AreEqual("+61 2 96996099", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+61 2 96996088", response.AdminContact.FaxNumber);
            Assert.AreEqual("dmain@netregistry.com.au", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("PO BOX 270", response.AdminContact.Address[0]);
            Assert.AreEqual("Broadway", response.AdminContact.Address[1]);
            Assert.AreEqual("AU (AUSTRALIA)", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("NETREGISTRY PTY LTD", response.TechnicalContact.Name);
            Assert.AreEqual("+61 2 9699 6099", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+61 2 9699 6088", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dnsadmin@netregistry.com.au", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("PO Box 270", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Broadway", response.TechnicalContact.Address[1]);
            Assert.AreEqual("2007", response.TechnicalContact.Address[2]);
            Assert.AreEqual("AU (AUSTRALIA)", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.netregistry.net", response.NameServers[0]);
            Assert.AreEqual("ns2.netregistry.net", response.NameServers[1]);
            Assert.AreEqual("ns3.netregistry.net", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("210 PendingRelease", response.DomainStatus[0]);

            Assert.AreEqual("no", response.DnsSecStatus);
            Assert.AreEqual(31, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "throttled.txt");
            var response = parser.Parse("whois.srs.net.nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.srs.net.nz/nz/Found", response.TemplateName);

            Assert.AreEqual("jaycar.co.nz", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("440 Request Denied", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "not_found.txt");
            var response = parser.Parse("whois.srs.net.nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.srs.net.nz/nz/Found", response.TemplateName);

            Assert.AreEqual("u34jedzcq.co.nz", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("220 Available", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "invalid.txt");
            var response = parser.Parse("whois.srs.net.nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Invalid, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.srs.net.nz/nz/Found", response.TemplateName);

            Assert.AreEqual("u34jedzcq.nz", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("500 Invalid characters in query string", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "found.txt");
            var response = parser.Parse("whois.srs.net.nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.srs.net.nz/nz/Found", response.TemplateName);

            Assert.AreEqual("google.co.nz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1 208 3895740", response.Registrar.AbuseTelephoneNumber);


             // Registrant Details
            Assert.AreEqual("Google Inc", response.Registrant.Name);
            Assert.AreEqual("+1 650 +1 650 3300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1 650 +1 650 6181434", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US (UNITED STATES)", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("Google Inc", response.AdminContact.Name);
            Assert.AreEqual("+1 650 +1 650 3300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1 650 +1 650 6181434", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US (UNITED STATES)", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("Google Inc", response.TechnicalContact.Name);
            Assert.AreEqual("+1 650 +1 650 3300100", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+  +1 650 6181434", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US (UNITED STATES)", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("200 Active", response.DomainStatus[0]);

            Assert.AreEqual("no", response.DnsSecStatus);
            Assert.AreEqual(38, response.FieldsParsed);
        }
    }
}
