using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Be.Be
{
    [TestFixture]
    public class BeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dns.be", "be", "found.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/Found", response.TemplateName);

            Assert.AreEqual("register.be", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Register NV/SA", response.Registrar.Name);
            Assert.AreEqual("www.register.be", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2000, 12, 12, 0, 0, 0), response.Registered);

             // TechnicalContact Details
            Assert.AreEqual("Register.be Technical Support", response.TechnicalContact.Name);
            Assert.AreEqual("Register.be", response.TechnicalContact.Organization);
            Assert.AreEqual("+32.22473720", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+32.22473701", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("info@register.be", response.TechnicalContact.Email);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("NOT AVAILABLE", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "not_found.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.be", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);        
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "error.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Error, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/Error", response.TemplateName);

            Assert.AreEqual("www.kimdemolenaer.be", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_not_available()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "not_available.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/Found", response.TemplateName);

            Assert.AreEqual("gratisdatingplaza.be", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("AXC", response.Registrar.Name);
            Assert.AreEqual("axc.nl/", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2011, 2, 15, 0, 0, 0), response.Registered);

             // TechnicalContact Details
            Assert.AreEqual("R. Bashir", response.TechnicalContact.Name);
            Assert.AreEqual("AXC", response.TechnicalContact.Organization);
            Assert.AreEqual("+31.787112586", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+31.787112587", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("support@axc.nl", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2594.hostgator.com", response.NameServers[0]);
            Assert.AreEqual("ns2593.hostgator.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("NOT AVAILABLE", response.DomainStatus[0]);

            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_out_of_service()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "out_of_service.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.OutOfService, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/OutOfService", response.TemplateName);

            Assert.AreEqual("ee", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2000, 12, 14, 0, 0, 0), response.Registered);

            // Registrar
            Assert.AreEqual("www.dns.be", response.Registrar.Url);

             // TechnicalContact Details
            Assert.AreEqual("DNS BE Tech", response.TechnicalContact.Name);
            Assert.AreEqual("DNS BE vzw", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Ubicenter", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Philipssite 5 bus 13", response.TechnicalContact.Address[1]);
            Assert.AreEqual("300 Leuven", response.TechnicalContact.Address[2]);
            Assert.AreEqual("BE", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+32.16284970", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+32.16284971", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("tech@dns.be", response.TechnicalContact.Email);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OUT OF SERVICE", response.DomainStatus[0]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_quarantined()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "quarantined.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Quarantined, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/Quarantined", response.TemplateName);

            Assert.AreEqual("9i", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2003, 12, 22, 0, 0, 0), response.Registered);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("QUARANTINE", response.DomainStatus[0]);

            Assert.AreEqual(4, response.FieldsParsed);
        }

        [Test]
        public void Test_blocked()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "blocked.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Blocked, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "throttled.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_throttled_response_throttled_limit()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "throttled_response_throttled_limit.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "not_found_status_available.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.be", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "invalid.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Error, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/Error", response.TemplateName);

            Assert.AreEqual("www.kimdemolenaer.be", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);
        }

        [Test]
        public void Test_youtube()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "youtu.be.txt");
            var response = parser.Parse("whois.dns.be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.be/be/Found", response.TemplateName);

            Assert.AreEqual("youtu.be", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2007, 12, 24, 0, 0, 0), response.Registered);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns4.google.com", response.NameServers[0]);
            Assert.AreEqual("ns3.google.com", response.NameServers[1]);
            Assert.AreEqual("ns1.google.com", response.NameServers[2]);
            Assert.AreEqual("ns2.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("NOT AVAILABLE", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);        
        }
    }
}
