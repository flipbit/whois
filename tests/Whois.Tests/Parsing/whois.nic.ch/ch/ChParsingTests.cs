using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ch.Ch
{
    [TestFixture]
    public class ChParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ch", "ch", "found.txt");
            var response = parser.Parse("whois.nic.ch", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ch/ch/Found", response.TemplateName);

            Assert.AreEqual("ggoogle.ch", response.DomainName.ToString());

             // Registrant Details
            Assert.AreEqual("EISD John", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Room 208, Furong Road, Changsha City", response.Registrant.Address[0]);
            Assert.AreEqual("CN-41000 Changsha", response.Registrant.Address[1]);
            Assert.AreEqual("China", response.Registrant.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("xie huijie", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("xie huijie", response.TechnicalContact.Address[0]);
            Assert.AreEqual("No95.Lane768.Ruili Road.Minhang District", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CN-200240 shanghai", response.TechnicalContact.Address[2]);
            Assert.AreEqual("China", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns3.domainmanager.com", response.NameServers[0]);
            Assert.AreEqual("ns4.domainmanager.com", response.NameServers[1]);

            Assert.AreEqual("N", response.DnsSecStatus);
            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.nic.ch", "ch", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.nic.ch", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ch/ch/Found", response.TemplateName);

            Assert.AreEqual("pui.ch", response.DomainName.ToString());

             // Registrant Details
            Assert.AreEqual("Keller Philipp", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Schauenbergstrasse 26", response.Registrant.Address[0]);
            Assert.AreEqual("CH-8046 Zürich", response.Registrant.Address[1]);
            Assert.AreEqual("Switzerland", response.Registrant.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("Keller Philipp", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Schauenbergstrasse 26", response.TechnicalContact.Address[0]);
            Assert.AreEqual("CH-8046 Zürich", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Switzerland", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.citrin.ch", response.NameServers[0]);
            Assert.AreEqual("ns1.citrin.ch", response.NameServers[1]);
            Assert.AreEqual("ns2.citrin.ch", response.NameServers[2]);
            Assert.AreEqual("ns2.citrin.ch", response.NameServers[3]);

            Assert.AreEqual("N", response.DnsSecStatus);
            Assert.AreEqual(15, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ch", "ch", "not_found.txt");
            var response = parser.Parse("whois.nic.ch", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ch/ch/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.ch", "ch", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.ch", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ch/ch/Found", response.TemplateName);

            Assert.AreEqual("google.ch", response.DomainName.ToString());

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Administrator Domain", response.Registrant.Address[0]);
            Assert.AreEqual("Amphitheatre Parkway 1600", response.Registrant.Address[1]);
            Assert.AreEqual("US-94043 Mountain View, CA", response.Registrant.Address[2]);
            Assert.AreEqual("United States", response.Registrant.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Address[0]);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US-94043 Mountain View", response.TechnicalContact.Address[2]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual("N", response.DnsSecStatus);
            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
