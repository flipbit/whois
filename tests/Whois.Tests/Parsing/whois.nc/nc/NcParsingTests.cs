using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nc.Nc
{
    public class NcParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public NcParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "found", "found.txt");
            var response = parser.Parse("whois.nc", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nc/nc/found/01", response.TemplateName);

            Assert.Equal("rya.nc", response.DomainName.ToString());

            Assert.Equal(new DateTime(2013, 03, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2013, 03, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 03, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("PLAY NEW CALEDONIA", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("12 BOULEVARD VAUBAN", response.Registrant.Address[0]);
            Assert.Equal("BP 2839", response.Registrant.Address[1]);
            Assert.Equal("98846 NOUMEA CEDEX", response.Registrant.Address[2]);

            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.linode.com", response.NameServers[0]);
            Assert.Equal("ns2.linode.com", response.NameServers[1]);
            Assert.Equal("ns3.linode.com", response.NameServers[2]);

            Assert.Equal(12, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_contact_without_state_and_address()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "found", "found_contact_without_state_and_address.txt");
            var response = parser.Parse("whois.nc", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nc/nc/found/01", response.TemplateName);

            Assert.Equal("gouv.nc", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 10, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 10, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2012, 10, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("DTSI", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(2, response.Registrant.Address.Count);
            Assert.Equal("BP 15101", response.Registrant.Address[0]);
            Assert.Equal("98804 NOUMEA CEDEX", response.Registrant.Address[1]);

            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.gouv.nc", response.NameServers[0]);
            Assert.Equal("ns2.gouv.nc", response.NameServers[1]);
            Assert.Equal("ns3.gouv.nc", response.NameServers[2]);

            Assert.Equal(11, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nc", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/06", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.nc", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nc/nc/found/01", response.TemplateName);

            Assert.Equal("domaine.nc", response.DomainName.ToString());

            Assert.Equal(new DateTime(2013, 04, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 05, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2016, 05, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("CCTLD", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1 RUE MONCHOVET", response.Registrant.Address[0]);
            Assert.Equal("7 EME ETAGE", response.Registrant.Address[1]);
            Assert.Equal("LE WARUNA 1", response.Registrant.Address[2]);
            Assert.Equal("98841 NOUMEA CEDEX", response.Registrant.Address[3]);
            Assert.Equal("NEW CALEDONIA", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("any-ns1.nc", response.NameServers[0]);
            Assert.Equal("ns1.nc", response.NameServers[1]);
            Assert.Equal("ns2.nc", response.NameServers[2]);

            Assert.Equal(14, response.FieldsParsed);
        }
    }
}
