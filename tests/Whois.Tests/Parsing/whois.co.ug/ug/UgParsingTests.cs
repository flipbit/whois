using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Co.Ug.Ug
{
    public class UgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public UgParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "found.txt");
            var response = parser.Parse("whois.co.ug", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.co.ug/ug/Found", response.TemplateName);

            Assert.Equal("whois.co.ug", response.DomainName.ToString());

            Assert.Equal(new DateTime(2009, 11, 10, 14, 06, 58, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2001, 04, 02, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2018, 04, 07, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("CM260", response.AdminContact.RegistryId);
            Assert.Equal("Charles Musisi", response.AdminContact.Name);
            Assert.Equal("+256 31 230 1800", response.AdminContact.TelephoneNumber);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("Computer Frontiers International, Plot 6B Windsor Loop, P.O. Box 12", response.AdminContact.Address[0]);
            Assert.Equal("Kampala", response.AdminContact.Address[1]);
            Assert.Equal("Uganda", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("MJ5-UG", response.TechnicalContact.RegistryId);
            Assert.Equal("Mpeirwe Johnson", response.TechnicalContact.Name);
            Assert.Equal("+256782694615", response.TechnicalContact.TelephoneNumber);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("Plot 6B, Windor Loop Kitante", response.TechnicalContact.Address[0]);
            Assert.Equal("Kampala", response.TechnicalContact.Address[1]);
            Assert.Equal("Uganda", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.cfi.co.ug", response.NameServers[0]);
            Assert.Equal("ns2.cfi.co.ug", response.NameServers[1]);
            Assert.Equal("ns3.cfi.co.ug", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(23, response.FieldsParsed);
            AssertWriter.Write(response);
        }

        [Fact]
        public void Test_unconfirmed()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "unconfirmed.txt");
            var response = parser.Parse("whois.co.ug", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Unconfirmed, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.co.ug/ug/Found", response.TemplateName);

            Assert.Equal("youtube.ug", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 11, 01, 23, 27, 38, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 11, 01, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 11, 01, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("UNCONFIRMED", response.DomainStatus[0]);

            Assert.Equal(18, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "not_found.txt");
            var response = parser.Parse("whois.co.ug", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.co.ug/ug/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "found_status_registered.txt");
            var response = parser.Parse("whois.co.ug", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.co.ug/ug/Found", response.TemplateName);

            Assert.Equal("whois.co.ug", response.DomainName.ToString());

            Assert.Equal(new DateTime(2009, 11, 10, 14, 06, 58, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2001, 04, 02, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2018, 04, 07, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("CM260", response.AdminContact.RegistryId);
            Assert.Equal("Charles Musisi", response.AdminContact.Name);
            Assert.Equal("+256 31 230 1800", response.AdminContact.TelephoneNumber);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("Computer Frontiers International, Plot 6B Windsor Loop, P.O. Box 12", response.AdminContact.Address[0]);
            Assert.Equal("Kampala", response.AdminContact.Address[1]);
            Assert.Equal("Uganda", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("MJ5-UG", response.TechnicalContact.RegistryId);
            Assert.Equal("Mpeirwe Johnson", response.TechnicalContact.Name);
            Assert.Equal("+256782694615", response.TechnicalContact.TelephoneNumber);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("Plot 6B, Windor Loop Kitante", response.TechnicalContact.Address[0]);
            Assert.Equal("Kampala", response.TechnicalContact.Address[1]);
            Assert.Equal("Uganda", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.cfi.co.ug", response.NameServers[0]);
            Assert.Equal("ns2.cfi.co.ug", response.NameServers[1]);
            Assert.Equal("ns3.cfi.co.ug", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(23, response.FieldsParsed);
        }
    }
}
