using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Io.Io
{
    public class IoParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public IoParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.io", "io", "found.txt");
            var response = parser.Parse("whois.nic.io", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.io/io/Found", response.TemplateName);

            Assert.Equal("google.io", response.DomainName.ToString());

            Assert.Equal(new DateTime(2013, 09, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("GOOGLE INC.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("US", response.Registrant.Address[3]);

            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Live", response.DomainStatus[0]);

            Assert.Equal(13, response.FieldsParsed);
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.io", "io", "reserved.txt");
            var response = parser.Parse("whois.nic.io", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.io/io/Reserved", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.io", "io", "not_found.txt");
            var response = parser.Parse("whois.nic.io", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.io/io/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.io", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.io", "io", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.io", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.io/io/Found", response.TemplateName);

            Assert.Equal("redis.io", response.DomainName.ToString());

            Assert.Equal(new DateTime(2014, 05, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Salvatore Sanfilippo", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Salvatore Sanfilippo", response.Registrant.Address[0]);
            Assert.Equal("Via F.Alaimo, 2", response.Registrant.Address[1]);
            Assert.Equal("Campobello di Licata (AG", response.Registrant.Address[2]);
            Assert.Equal("IT", response.Registrant.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.iwantmyname.net", response.NameServers[0]);
            Assert.Equal("ns2.iwantmyname.net", response.NameServers[1]);
            Assert.Equal("ns3.iwantmyname.net", response.NameServers[2]);
            Assert.Equal("ns4.iwantmyname.net", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Live", response.DomainStatus[0]);

            Assert.Equal(13, response.FieldsParsed);
        }
    }
}
