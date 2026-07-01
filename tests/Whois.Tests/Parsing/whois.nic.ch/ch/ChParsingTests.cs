using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ch.Ch
{
    public class ChParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ChParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ch", "ch", "found.txt");
            var response = parser.Parse("whois.nic.ch", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ch/ch/Found", response.TemplateName);

            Assert.Equal("ggoogle.ch", response.DomainName.ToString());

             // Registrant Details
            Assert.Equal("EISD John", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Room 208, Furong Road, Changsha City", response.Registrant.Address[0]);
            Assert.Equal("CN-41000 Changsha", response.Registrant.Address[1]);
            Assert.Equal("China", response.Registrant.Address[2]);


             // TechnicalContact Details
            Assert.Equal("xie huijie", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("xie huijie", response.TechnicalContact.Address[0]);
            Assert.Equal("No95.Lane768.Ruili Road.Minhang District", response.TechnicalContact.Address[1]);
            Assert.Equal("CN-200240 shanghai", response.TechnicalContact.Address[2]);
            Assert.Equal("China", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns3.domainmanager.com", response.NameServers[0]);
            Assert.Equal("ns4.domainmanager.com", response.NameServers[1]);

            Assert.Equal("N", response.DnsSecStatus);
            Assert.Equal(14, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.nic.ch", "ch", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.nic.ch", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ch/ch/Found", response.TemplateName);

            Assert.Equal("pui.ch", response.DomainName.ToString());

             // Registrant Details
            Assert.Equal("Keller Philipp", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Schauenbergstrasse 26", response.Registrant.Address[0]);
            Assert.Equal("CH-8046 Zürich", response.Registrant.Address[1]);
            Assert.Equal("Switzerland", response.Registrant.Address[2]);


             // TechnicalContact Details
            Assert.Equal("Keller Philipp", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("Schauenbergstrasse 26", response.TechnicalContact.Address[0]);
            Assert.Equal("CH-8046 Zürich", response.TechnicalContact.Address[1]);
            Assert.Equal("Switzerland", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.citrin.ch", response.NameServers[0]);
            Assert.Equal("ns1.citrin.ch", response.NameServers[1]);
            Assert.Equal("ns2.citrin.ch", response.NameServers[2]);
            Assert.Equal("ns2.citrin.ch", response.NameServers[3]);

            Assert.Equal("N", response.DnsSecStatus);
            Assert.Equal(15, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ch", "ch", "not_found.txt");
            var response = parser.Parse("whois.nic.ch", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ch/ch/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.ch", "ch", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.ch", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ch/ch/Found", response.TemplateName);

            Assert.Equal("google.ch", response.DomainName.ToString());

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Administrator Domain", response.Registrant.Address[0]);
            Assert.Equal("Amphitheatre Parkway 1600", response.Registrant.Address[1]);
            Assert.Equal("US-94043 Mountain View, CA", response.Registrant.Address[2]);
            Assert.Equal("United States", response.Registrant.Address[3]);


             // TechnicalContact Details
            Assert.Equal("Google Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("DNS Admin", response.TechnicalContact.Address[0]);
            Assert.Equal("2400 E. Bayshore Pkwy", response.TechnicalContact.Address[1]);
            Assert.Equal("US-94043 Mountain View", response.TechnicalContact.Address[2]);
            Assert.Equal("United States", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal("N", response.DnsSecStatus);
            Assert.Equal(17, response.FieldsParsed);
        }
    }
}
