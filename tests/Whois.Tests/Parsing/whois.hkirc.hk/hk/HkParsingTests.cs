using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Hkirc.Hk.Hk
{
    public class HkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public HkParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.hkirc.hk", "hk", "found", "brighter.com.hk.txt");
            var response = parser.Parse("whois.hkirc.hk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.hkirc.hk/hk/found/01", response.TemplateName);

            Assert.Equal("brighter.com.hk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Hong Kong Domain Name Registration Company Limited", response.Registrar.Name);
            Assert.Equal("enquiry@hkdnr.hk", response.Registrar.AbuseEmail);
            Assert.Equal("+852 2319 1313", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(1998, 12, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("THE BRIGHTER CO", response.Registrant.Name);
            Assert.Equal("qhau@neotech-hk.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(2, response.Registrant.Address.Count);
            Assert.Equal("FLAT F-H,14/F,WINNER INDUSTRIAL BLDG.,", response.Registrant.Address[0]);
            Assert.Equal("HK", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.Equal("HK2763316T", response.AdminContact.RegistryId);
            Assert.Equal("THE BRIGHTER COMPANY", response.AdminContact.Organization);
            Assert.Equal("+852-23426328", response.AdminContact.TelephoneNumber);
            Assert.Equal("+852-23428180", response.AdminContact.FaxNumber);
            Assert.Equal("qhau@neotech-hk.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(2, response.AdminContact.Address.Count);
            Assert.Equal("FLAT F-H,14/F,WINNER INDUSTRIAL BLDG.,55 HUNG TO ROAD,KWUN TONG, KOWLOON", response.AdminContact.Address[0]);
            Assert.Equal("HK", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.Equal("HAU", response.TechnicalContact.Name);
            Assert.Equal("THE BRIGHTER COMPANY", response.TechnicalContact.Organization);
            Assert.Equal("+852-23426328", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+852-23428180", response.TechnicalContact.FaxNumber);
            Assert.Equal("qhau@neotech-hk.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(2, response.TechnicalContact.Address.Count);
            Assert.Equal("FLAT F-H,14/F,WINNER INDUSTRIAL BLDG.,", response.TechnicalContact.Address[0]);
            Assert.Equal("HK", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns5.hostingspeed.net", response.NameServers[0]);
            Assert.Equal("ns2.hostingspeed.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Complete", response.DomainStatus[0]);

            Assert.Equal(27, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.hkirc.hk", "hk", "not-found", "not_found.txt");
            var response = parser.Parse("whois.hkirc.hk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.hkirc.hk/hk/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.hkirc.hk", "hk", "found", "google.hk.txt");
            var response = parser.Parse("whois.hkirc.hk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.hkirc.hk/hk/found/01", response.TemplateName);

            Assert.Equal("google.hk", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MARKMONITOR INC.", response.Registrar.Name);

            Assert.Equal(new DateTime(2004, 04, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 03, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("GOOGLE INC.", response.Registrant.Name);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(2, response.Registrant.Address.Count);
            Assert.Equal("1600 AMPHITHEATRE PARKWAY   94043", response.Registrant.Address[0]);
            Assert.Equal("US", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.Equal("HK3602487T", response.AdminContact.RegistryId);
            Assert.Equal("GOOGLE INC.", response.AdminContact.Organization);
            Assert.Equal("+1-6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1-6502530001", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(2, response.AdminContact.Address.Count);
            Assert.Equal("1600 AMPHITHEATRE PARKWAY   94043", response.AdminContact.Address[0]);
            Assert.Equal("US", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.Equal("ADMIN", response.TechnicalContact.Name);
            Assert.Equal("GOOGLE INC.", response.TechnicalContact.Organization);
            Assert.Equal("+1-6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1-6502530001", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(2, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 AMPHITHEATRE PARKWAY   94043", response.TechnicalContact.Address[0]);
            Assert.Equal("US", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Complete", response.DomainStatus[0]);

            Assert.Equal(28, response.FieldsParsed);
        }
    }
}
