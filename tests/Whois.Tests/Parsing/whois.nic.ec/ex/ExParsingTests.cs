using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ec.Ex
{
    public class ExParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ExParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ec", "ex", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.ec", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ec/ex/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.ec", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ec", "ex", "found", "found.txt");
            var response = parser.Parse("whois.nic.ec", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ec/ex/found/01", response.TemplateName);

            Assert.Equal("google.ec", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 09, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2003, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Registrant Details
            Assert.Equal("Rose Hagan", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("1-6503300100", response.Registrant.TelephoneNumber);
            Assert.Equal("1-6503300100", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, CA 94043", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("Domain Provisioning", response.AdminContact.Name);
            Assert.Equal("MarkMonitor", response.AdminContact.Organization);
            Assert.Equal("1208-3895799", response.AdminContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("10400 Overland Rd.,PMB 155", response.AdminContact.Address[0]);
            Assert.Equal("Boise, Idaho 83709", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(27, response.FieldsParsed);
        }
    }
}
