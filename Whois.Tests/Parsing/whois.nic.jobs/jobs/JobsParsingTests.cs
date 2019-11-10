using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Jobs.Jobs
{
    [TestFixture]
    public class JobsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.jobs", "jobs", "found.txt");
            var response = parser.Parse("whois.nic.jobs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.jobs/jobs/Found", response.TemplateName);

            Assert.AreEqual("example.jobs", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("EMPLOY MEDIA LLC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2006, 02, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 02, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

            Assert.AreEqual(5, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.jobs", "jobs", "not_found.txt");
            var response = parser.Parse("whois.nic.jobs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.jobs/jobs/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.jobs", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.jobs", "jobs", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.jobs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.jobs/jobs/Found", response.TemplateName);

            Assert.AreEqual("google.jobs", response.DomainName.ToString());
            Assert.AreEqual("86932313_DOMAIN_JOBS-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MARKMONITOR INC.", response.Registrar.Name);
            Assert.AreEqual("292", response.Registrar.IanaId);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2017, 07, 27, 20, 59, 01, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 09, 15, 04, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 09, 15, 04, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(18, response.FieldsParsed);
        }
    }
}
