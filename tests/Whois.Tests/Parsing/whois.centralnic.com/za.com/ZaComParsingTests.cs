using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.ZaCom
{
    public class ZaComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ZaComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "za.com", "not-found", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "za.com", "found", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

            Assert.Equal("siyenza.za.com", response.DomainName.ToString());
            Assert.Equal("CNIC-DO333077", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Megaweb Internet Services", response.Registrar.Name);
            Assert.Equal("http://www.megaweb.co.za/", response.Registrar.Url);
            Assert.Equal("02711 485 1984", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 12, 3, 12, 33, 13, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 11, 17, 11, 47, 29, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 11, 17, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("H1063006", response.Registrant.RegistryId);
            Assert.Equal("MegaWeb Internet Services cc", response.Registrant.Name);
            Assert.Equal("+27.0114851984", response.Registrant.TelephoneNumber);
            Assert.Equal("dns-admin@megaweb.co.za", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("PO Box 3738", response.Registrant.Address[0]);
            Assert.Equal("Cramerview", response.Registrant.Address[1]);
            Assert.Equal("2060", response.Registrant.Address[2]);
            Assert.Equal("ZA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("H119106", response.AdminContact.RegistryId);
            Assert.Equal("Liz Hart", response.AdminContact.Name);
            Assert.Equal("Siyenza Management", response.AdminContact.Organization);
            Assert.Equal("+27.0114851984", response.AdminContact.TelephoneNumber);
            Assert.Equal("dns-admin@megaweb.co.za", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("PO Box 3738", response.AdminContact.Address[0]);
            Assert.Equal("Cramerview", response.AdminContact.Address[1]);
            Assert.Equal("2060", response.AdminContact.Address[2]);
            Assert.Equal("ZA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("C12112", response.TechnicalContact.RegistryId);
            Assert.Equal("Laida Peters", response.TechnicalContact.Name);
            Assert.Equal("Megaweb Internet Services", response.TechnicalContact.Organization);
            Assert.Equal("+27.027114851984", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("dns-admin@megaweb.co.za", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("Gauteng", response.TechnicalContact.Address[0]);
            Assert.Equal("2192", response.TechnicalContact.Address[1]);
            Assert.Equal("ZA", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1a.your-server.co.za", response.NameServers[0]);
            Assert.Equal("nsa.second-ns.co.za", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(38, response.FieldsParsed);
        }
    }
}
