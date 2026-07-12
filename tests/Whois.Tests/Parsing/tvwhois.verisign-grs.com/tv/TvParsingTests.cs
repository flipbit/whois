using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Tvwhois.Verisign.Grs.Com.Tv
{
    public class TvParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public TvParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "found", "found.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(7, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);

            Assert.Equal("set.tv", response.DomainName.ToString());

            Assert.Equal(".TV RESERVED DOMAINS", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 3, 18, 0, 0, 0), response.Updated);
            Assert.Equal(new DateTime(2010, 3, 18, 0, 0, 0), response.Registered);
            Assert.Equal(new DateTime(2011, 3, 18, 0, 0, 0), response.Expiration);

            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("SERVER-XFER-PROHIBITED", response.DomainStatus[0]);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "not-found", "u34jedzcq.tv.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(2, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);

            Assert.Equal("u34jedzcq.tv", response.DomainName.ToString());
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "found", "found_status_registered.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(21, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);

            Assert.Equal("google.tv", response.DomainName.ToString());

            Assert.Equal("MARKMONITOR INC.", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.Equal("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2017, 7, 1, 09, 25, 47, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2002, 8, 2, 16, 43, 36, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2018, 8, 2, 16, 43, 36, DateTimeKind.Utc), response.Expiration);

            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);

            Assert.Equal(6, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.Equal("serverDeleteProhibited", response.DomainStatus[3]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[4]);
            Assert.Equal("serverUpdateProhibited", response.DomainStatus[5]);

            Assert.Equal("unsigned", response.DnsSecStatus);
        }
    }
}
