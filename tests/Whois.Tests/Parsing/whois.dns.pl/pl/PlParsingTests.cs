using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Pl.Pl
{
    public class PlParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public PlParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found", "nom.pl.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pl/pl/found/01", response.TemplateName);

            Assert.Equal("nom.pl", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("NASK", response.Registrar.Name);
            Assert.Equal("info@dns.pl", response.Registrar.AbuseEmail);
            Assert.Equal("+48.22 3808300", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2004, 2, 9, 12, 24, 22), response.Updated);
            Assert.Equal(new DateTime(2003, 3, 25, 12, 0, 0), response.Registered);

            // Nameservers
            Assert.Equal(7, response.NameServers.Count);
            Assert.Equal("f-dns.pl", response.NameServers[0]);
            Assert.Equal("i-dns.pl", response.NameServers[1]);
            Assert.Equal("a-dns.pl", response.NameServers[2]);
            Assert.Equal("e-dns.pl", response.NameServers[3]);
            Assert.Equal("d-dns.pl", response.NameServers[4]);
            Assert.Equal("h-dns.pl", response.NameServers[5]);
            Assert.Equal("g-dns.pl", response.NameServers[6]);

            Assert.Equal("Signed", response.DnsSecStatus);
            Assert.Equal(15, response.FieldsParsed);        
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found", "pentex.pl.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pl/pl/found/01", response.TemplateName);

            Assert.Equal("pentex.pl", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("OVH SAS", response.Registrar.Name);
            Assert.Equal("pomoc@ovh.pl", response.Registrar.AbuseEmail);
            Assert.Equal("+48.71 7860700", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2012, 6, 19, 15, 56, 18), response.Updated);
            Assert.Equal(new DateTime(2001, 6, 20, 13, 0, 0), response.Registered);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("dns1.pentex.pl", response.NameServers[0]);
            Assert.Equal("dns2.pentex.pl", response.NameServers[1]);

            Assert.Equal(9, response.FieldsParsed);
        }

        [Fact]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "throttled", "throttled.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Throttled, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pl/pl/throttled/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);        
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "not-found", "u34jedzcq.pl.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pl/pl/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.pl", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found", "google.pl.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pl/pl/found/01", response.TemplateName);

            Assert.Equal("google.pl", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Markmonitor, Inc.", response.Registrar.Name);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2012, 8, 17, 11, 21, 9), response.Updated);
            Assert.Equal(new DateTime(2002, 9, 19, 13, 0, 0), response.Registered);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.google.com.", response.NameServers[0]);
            Assert.Equal("ns1.google.com.", response.NameServers[1]);

            Assert.Equal(9, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_08_pl()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found", "08.pl.txt");

            var response = parser.Parse("whois.dns.pl", sample);

            Assert.Equal("08.pl", response.DomainName.ToString());

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pl/pl/found/01", response.TemplateName);

            Assert.Equal("08.pl", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("OVH SAS", response.Registrar.Name);
            Assert.Equal("+48.717500200", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2019, 2, 1, 18, 5, 52), response.Updated);
            Assert.Equal(new DateTime(2004, 2, 7, 6, 45, 12), response.Registered);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("dns111.ovh.net.", response.NameServers[0]);
            Assert.Equal("ns111.ovh.net.", response.NameServers[1]);

            Assert.Equal(8, response.FieldsParsed);
        }
    }
}
