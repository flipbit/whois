using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Jobs.Jobs
{
    public class JobsParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public JobsParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.jobs", "jobs", "found", "found.txt");
            var response = parser.Parse("whois.nic.jobs", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.jobs/jobs/found/01", response.TemplateName);

            Assert.Equal("example.jobs", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("EMPLOY MEDIA LLC", response.Registrar.Name);

            Assert.Equal(new DateTime(2006, 02, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 02, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

            Assert.Equal(5, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.jobs", "jobs", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.jobs", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.jobs/jobs/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.jobs", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.jobs", "jobs", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.jobs", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.jobs/jobs/found/01", response.TemplateName);

            Assert.Equal("google.jobs", response.DomainName.ToString());
            Assert.Equal("86932313_DOMAIN_JOBS-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MARKMONITOR INC.", response.Registrar.Name);
            Assert.Equal("292", response.Registrar.IanaId);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.Equal("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2017, 07, 27, 20, 59, 01, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2005, 09, 15, 04, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2017, 09, 15, 04, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(18, response.FieldsParsed);
        }
    }
}
