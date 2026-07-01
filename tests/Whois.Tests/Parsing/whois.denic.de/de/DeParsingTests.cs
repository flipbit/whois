using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Denic.De.De
{
    public class DeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public DeParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "found.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Found", response.TemplateName);

            Assert.Equal("prodns.de", response.DomainName.ToString());

            Assert.Equal(new DateTime(2013, 12, 4, 13, 42, 43, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.Equal("Prohost Role", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Koepenweg 8", response.AdminContact.Address[0]);
            Assert.Equal("27616", response.AdminContact.Address[1]);
            Assert.Equal("Lunestedt", response.AdminContact.Address[2]);
            Assert.Equal("DE", response.AdminContact.Address[3]);

            Assert.Equal("+49 4748 947983", response.AdminContact.TelephoneNumber);
            Assert.Equal("+49 4748 947984", response.AdminContact.FaxNumber);
            Assert.Equal("hostmaster@prohost.de", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.Equal("Prohost Role", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Koepenweg 8", response.TechnicalContact.Address[0]);
            Assert.Equal("27616", response.TechnicalContact.Address[1]);
            Assert.Equal("Lunestedt", response.TechnicalContact.Address[2]);
            Assert.Equal("DE", response.TechnicalContact.Address[3]);

            Assert.Equal("+49 4748 947983", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+49 4748 947984", response.TechnicalContact.FaxNumber);
            Assert.Equal("hostmaster@prohost.de", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.prodns.eu", response.NameServers[0]);
            Assert.Equal("ns4.prodns.eu", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("connect", response.DomainStatus[0]);

            Assert.Equal(22, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_technical_contact()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "found_technical_contact.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Found", response.TemplateName);

            Assert.Equal("google.de", response.DomainName.ToString());

            Assert.Equal(new DateTime(2010, 9, 8, 20, 40, 48, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.Equal("Domain Admin", response.AdminContact.Name);
            Assert.Equal("MarkMonitor Inc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("391 N Ancestor Pl", response.AdminContact.Address[0]);
            Assert.Equal("83704", response.AdminContact.Address[1]);
            Assert.Equal("Boise", response.AdminContact.Address[2]);
            Assert.Equal("US", response.AdminContact.Address[3]);

            Assert.Equal("+1.2083895740", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.AdminContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

             // TechnicalContact Details
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("94043", response.TechnicalContact.Address[1]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[2]);
            Assert.Equal("US", response.TechnicalContact.Address[3]);

            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com.", response.NameServers[0]);
            Assert.Equal("ns2.google.com.", response.NameServers[1]);
            Assert.Equal("ns3.google.com.", response.NameServers[2]);
            Assert.Equal("ns4.google.com.", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("connect", response.DomainStatus[0]);

            Assert.Equal(26, response.FieldsParsed);
        }

        [Fact]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "error.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Error, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Error", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "throttled.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Throttled, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Throttled", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "not_found.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.de", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_failed()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "failed.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Failed, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Found", response.TemplateName);

            Assert.Equal("msens.de", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 2, 23, 4, 36, 15, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.Equal("Daniel Andersson", response.AdminContact.Name);
            Assert.Equal("GUIDANCE INTERNATIONAL IP AB", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Landerigatan 1", response.AdminContact.Address[0]);
            Assert.Equal("50451", response.AdminContact.Address[1]);
            Assert.Equal("Borås", response.AdminContact.Address[2]);
            Assert.Equal("SE", response.AdminContact.Address[3]);

            Assert.Equal("+46.701434896", response.AdminContact.TelephoneNumber);
            Assert.Equal("+46.701434896", response.AdminContact.FaxNumber);
            Assert.Equal("info@guid-int.com", response.AdminContact.Email);

             // TechnicalContact Details
            Assert.Equal("Daniel Andersson", response.TechnicalContact.Name);
            Assert.Equal("GUIDANCE INTERNATIONAL IP AB", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Landerigatan 1", response.TechnicalContact.Address[0]);
            Assert.Equal("50451", response.TechnicalContact.Address[1]);
            Assert.Equal("Borås", response.TechnicalContact.Address[2]);
            Assert.Equal("SE", response.TechnicalContact.Address[3]);

            Assert.Equal("+46.701434896", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+46.701434896", response.TechnicalContact.FaxNumber);
            Assert.Equal("info@guid-int.com", response.TechnicalContact.Email);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("newreg-ns1.premiumregistrations.com", response.NameServers[0]);
            Assert.Equal("newreg-ns2.premiumregistrations.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("failed", response.DomainStatus[0]);

            Assert.Equal(24, response.FieldsParsed);
        }

        [Fact]
        public void Test_failed_status_failed_ace()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "failed_status_failed_ace.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Failed, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Found", response.TemplateName);

            Assert.Equal("xn--tstdomain-failed-nserver-qbc.de", response.DomainName.ToString());
            Assert.Equal("tästdomain-failed-nserver.de", response.DomainName.ToUnicodeString());

            Assert.Equal(new DateTime(2010, 6, 1, 8, 29, 38, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.Equal("Business Services", response.AdminContact.Name);
            Assert.Equal("DENIC eG", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Kaiserstrasse 75-77", response.AdminContact.Address[0]);
            Assert.Equal("60329", response.AdminContact.Address[1]);
            Assert.Equal("Frankfurt am Main", response.AdminContact.Address[2]);
            Assert.Equal("DE", response.AdminContact.Address[3]);

            Assert.Equal("+49 69 27235 272", response.AdminContact.TelephoneNumber);
            Assert.Equal("+49 69 27235 234", response.AdminContact.FaxNumber);
            Assert.Equal("dbs@denic.de", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.Equal("Business Services", response.TechnicalContact.Name);
            Assert.Equal("DENIC eG", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Kaiserstrasse 75-77", response.TechnicalContact.Address[0]);
            Assert.Equal("60329", response.TechnicalContact.Address[1]);
            Assert.Equal("Frankfurt am Main", response.TechnicalContact.Address[2]);
            Assert.Equal("DE", response.TechnicalContact.Address[3]);

            Assert.Equal("+49 69 27235 272", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+49 69 27235 234", response.TechnicalContact.FaxNumber);
            Assert.Equal("dbs@denic.de", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.denic.de.", response.NameServers[0]);
            Assert.Equal("ns2.denic.de.", response.NameServers[1]);
            Assert.Equal("ns3.denic.de.", response.NameServers[2]);
            Assert.Equal("ns4.denic.net.", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("failed", response.DomainStatus[0]);

            Assert.Equal(26, response.FieldsParsed);
        }

        [Fact]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "invalid.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Invalid, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Invalid", response.TemplateName);

            Assert.Equal("googlededewdedewdewde.foo.de", response.DomainName.ToString());

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("invalid", response.DomainStatus[0]);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "found_status_registered.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Found", response.TemplateName);

            Assert.Equal("google.de", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 3, 30, 17, 36, 27, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.Equal("Domain Admin", response.AdminContact.Name);
            Assert.Equal("MarkMonitor Inc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("391 N Ancestor Pl", response.AdminContact.Address[0]);
            Assert.Equal("83704", response.AdminContact.Address[1]);
            Assert.Equal("Boise", response.AdminContact.Address[2]);
            Assert.Equal("US", response.AdminContact.Address[3]);

            Assert.Equal("+1.2083895740", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.AdminContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

             // TechnicalContact Details
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("94043", response.TechnicalContact.Address[1]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[2]);
            Assert.Equal("US", response.TechnicalContact.Address[3]);

            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("connect", response.DomainStatus[0]);

            Assert.Equal(26, response.FieldsParsed);
        }
        
        [Fact]
        public void Test_found_amazon_de()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "amazon.de.txt");
            
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.denic.de/de/Found", response.TemplateName);

            Assert.Equal("amazon.de", response.DomainName.ToString());

            Assert.Equal(new DateTime(2018, 8, 10, 8, 41, 26, DateTimeKind.Utc), response.Updated);

            // Nameservers
            Assert.Equal(6, response.NameServers.Count);
            Assert.Equal("ns1.p31.dynect.net", response.NameServers[0]);
            Assert.Equal("ns2.p31.dynect.net", response.NameServers[1]);
            Assert.Equal("ns3.p31.dynect.net", response.NameServers[2]);
            Assert.Equal("ns4.p31.dynect.net", response.NameServers[3]);
            Assert.Equal("pdns1.ultradns.net", response.NameServers[4]);
            Assert.Equal("pdns6.ultradns.co.uk", response.NameServers[5]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("connect", response.DomainStatus[0]);

            Assert.Equal(10, response.FieldsParsed);
        }
    }
}
