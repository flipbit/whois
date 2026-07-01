using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Lu.Lu
{
    public class LuParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public LuParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dns.lu", "lu", "found.txt");
            var response = parser.Parse("whois.dns.lu", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.lu/lu/Found", response.TemplateName);

            Assert.Equal("arbed.lu", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Nameshield", response.Registrar.Name);
            Assert.Equal("http://www.nameshield.net", response.Registrar.Url);

            Assert.Equal(new DateTime(2008, 08, 11, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("ARCELORMITTAL", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("19, avenue de la liberte", response.Registrant.Address[0]);
            Assert.Equal("L-2930", response.Registrant.Address[1]);
            Assert.Equal("LUXEMBOURG", response.Registrant.Address[2]);
            Assert.Equal("LU", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("WEBER antoine", response.AdminContact.Name);
            Assert.Equal("pi@arcelormittal.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("ARCELORMITTAL LUXEMBOURG", response.AdminContact.Address[0]);
            Assert.Equal("19, avenue de la liberte", response.AdminContact.Address[1]);
            Assert.Equal("L-2930", response.AdminContact.Address[2]);
            Assert.Equal("LUXEMBOURG", response.AdminContact.Address[3]);
            Assert.Equal("LU", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("TECHNICAL Department", response.TechnicalContact.Name);
            Assert.Equal("technical@nameshield.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("NAMESHIELD", response.TechnicalContact.Address[0]);
            Assert.Equal("27 rue des arenes", response.TechnicalContact.Address[1]);
            Assert.Equal("49100", response.TechnicalContact.Address[2]);
            Assert.Equal("ANGERS", response.TechnicalContact.Address[3]);
            Assert.Equal("FR", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.arbed.lu", response.NameServers[0]);
            Assert.Equal("ns1.pt.lu", response.NameServers[1]);
            Assert.Equal("ns2.arbed.lu", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(28, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.lu", "lu", "not_found.txt");
            var response = parser.Parse("whois.dns.lu", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.lu/lu/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.lu", response.DomainName.ToString());


            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.lu", "lu", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.lu", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.lu/lu/Found", response.TemplateName);

            Assert.Equal("google.lu", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Markmonitor", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com/", response.Registrar.Url);

            Assert.Equal(new DateTime(2003, 06, 04, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("94043", response.Registrant.Address[1]);
            Assert.Equal("Mountain View", response.Registrant.Address[2]);
            Assert.Equal("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Google Inc.", response.AdminContact.Address[0]);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[1]);
            Assert.Equal("94043", response.AdminContact.Address[2]);
            Assert.Equal("Mountain View", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Google Inc.", response.TechnicalContact.Address[0]);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[1]);
            Assert.Equal("94043", response.TechnicalContact.Address[2]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(29, response.FieldsParsed);
        }
    }
}
