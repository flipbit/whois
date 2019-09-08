using System;
using System.IO;
using NUnit.Framework;
using Whois.Models;
using Whois.Net;

namespace Whois.Servers
{
    [TestFixture]
    public class IanaServerLookupTest
    {
        private IanaServerLookup lookup;
        private SampleReader reader;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            lookup = new IanaServerLookup();
            reader = new SampleReader();
        }

        [Test]
        public void TestLookupCom()
        {
            var response = reader.Read("whois.iana.org", "tld", "com.txt");
            TcpReaderFactory.Bind(() => new FakeTcpReader(response));

            var result = lookup.Lookup("test.com");

            Assert.IsNotNull(result);
            Assert.AreEqual(3, result.AdminContact.Address.Count);
            Assert.AreEqual("12061 Bluemont Way", result.AdminContact.Address[0]);
            Assert.AreEqual("Reston Virginia 20190", result.AdminContact.Address[1]);
            Assert.AreEqual("United States", result.AdminContact.Address[2]);
            Assert.AreEqual("info@verisign-grs.com", result.AdminContact.Email);
            Assert.AreEqual("+1 703 948 3978", result.AdminContact.FaxNumber);
            Assert.AreEqual("Registry Customer Service", result.AdminContact.Name);
            Assert.AreEqual("VeriSign Global Registry Services", result.AdminContact.Organization);
            Assert.AreEqual("+1 703 925-6999", result.AdminContact.TelephoneNumber);
            Assert.AreEqual(new DateTime(2012, 2, 15), result.Changed);
            Assert.AreEqual(new DateTime(1985, 1, 1), result.Created);
            Assert.AreEqual(13, result.NameServers.Count);
            Assert.AreEqual("a.gtld-servers.net", result.NameServers[0]);
            Assert.AreEqual("b.gtld-servers.net", result.NameServers[1]);
            Assert.AreEqual("c.gtld-servers.net", result.NameServers[2]);
            Assert.AreEqual("d.gtld-servers.net", result.NameServers[3]);
            Assert.AreEqual("e.gtld-servers.net", result.NameServers[4]);
            Assert.AreEqual("f.gtld-servers.net", result.NameServers[5]);
            Assert.AreEqual("g.gtld-servers.net", result.NameServers[6]);
            Assert.AreEqual("h.gtld-servers.net", result.NameServers[7]);
            Assert.AreEqual("i.gtld-servers.net", result.NameServers[8]);
            Assert.AreEqual("j.gtld-servers.net", result.NameServers[9]);
            Assert.AreEqual("k.gtld-servers.net", result.NameServers[10]);
            Assert.AreEqual("l.gtld-servers.net", result.NameServers[11]);
            Assert.AreEqual("m.gtld-servers.net", result.NameServers[12]);
            Assert.AreEqual(3, result.Organization.Address.Count);
            Assert.AreEqual("12061 Bluemont Way", result.Organization.Address[0]);
            Assert.AreEqual("Reston Virginia 20190", result.Organization.Address[1]);
            Assert.AreEqual("United States", result.Organization.Address[2]);
            Assert.AreEqual("VeriSign Global Registry Services", result.Organization.Name);
            Assert.AreEqual("Registration information: http://www.verisign-grs.com", result.Remarks);
            Assert.AreEqual("com", result.Tld);
            Assert.AreEqual(3, result.TechContact.Address.Count);
            Assert.AreEqual("12061 Bluemont Way", result.TechContact.Address[0]);
            Assert.AreEqual("Reston Virginia 20190", result.TechContact.Address[1]);
            Assert.AreEqual("United States", result.TechContact.Address[2]);
            Assert.AreEqual("info@verisign-grs.com", result.TechContact.Email);
            Assert.AreEqual("+1 703 948 3978", result.TechContact.FaxNumber);
            Assert.AreEqual("Registry Customer Service", result.TechContact.Name);
            Assert.AreEqual("VeriSign Global Registry Services", result.TechContact.Organization);
            Assert.AreEqual("+1 703 925-6999", result.TechContact.TelephoneNumber);
            Assert.AreEqual("whois.verisign-grs.com", result.Url);
        }

        [Test]
        public void TestLookupBe()
        {
            var response = reader.Read("whois.iana.org", "tld", "be.txt");
            TcpReaderFactory.Bind(() => new FakeTcpReader(response));

            var result = lookup.Lookup("test.be");

            Assert.IsNotNull(result);
            Assert.AreEqual(3, result.AdminContact.Address.Count);
            Assert.AreEqual("Ubicenter, Philipssite 5, bus 13", result.AdminContact.Address[0]);
            Assert.AreEqual("Leuven  3001", result.AdminContact.Address[1]);
            Assert.AreEqual("Belgium", result.AdminContact.Address[2]);
            Assert.AreEqual("legal@dnsbelgium.be", result.AdminContact.Email);
            Assert.AreEqual("+32 16 28 49 71", result.AdminContact.FaxNumber);
            Assert.AreEqual("Philip Du Bois", result.AdminContact.Name);
            Assert.AreEqual("DNS Belgium vzw/asbl", result.AdminContact.Organization);
            Assert.AreEqual("+32 16 28 49 70", result.AdminContact.TelephoneNumber);
            Assert.AreEqual(new DateTime(2014, 7, 30), result.Changed);
            Assert.AreEqual(new DateTime(1988, 8, 5), result.Created);
            Assert.AreEqual(6, result.NameServers.Count);
            Assert.AreEqual("a.ns.dns.be", result.NameServers[0]);
            Assert.AreEqual("b.ns.dns.be", result.NameServers[1]);
            Assert.AreEqual("c.ns.dns.be", result.NameServers[2]);
            Assert.AreEqual("d.ns.dns.be", result.NameServers[3]);
            Assert.AreEqual("x.ns.dns.be", result.NameServers[4]);
            Assert.AreEqual("y.ns.dns.be", result.NameServers[5]);
            Assert.AreEqual(3, result.Organization.Address.Count);
            Assert.AreEqual("Ubicenter, Philipssite 5, bus 13", result.Organization.Address[0]);
            Assert.AreEqual("Leuven  3001", result.Organization.Address[1]);
            Assert.AreEqual("Belgium", result.Organization.Address[2]);
            Assert.AreEqual("DNS Belgium vzw/asbl", result.Organization.Name);
            Assert.AreEqual("Registration information: http://www.dns.be", result.Remarks);
            Assert.AreEqual("be", result.Tld);
            Assert.AreEqual(3, result.TechContact.Address.Count);
            Assert.AreEqual("Ubicenter, Philipssite 5, bus 13", result.TechContact.Address[0]);
            Assert.AreEqual("Leuven  3001", result.TechContact.Address[1]);
            Assert.AreEqual("Belgium", result.TechContact.Address[2]);
            Assert.AreEqual("tech@dnsbelgium.be", result.TechContact.Email);
            Assert.AreEqual("+32 16 28 49 71", result.TechContact.FaxNumber);
            Assert.AreEqual("David Goelen", result.TechContact.Name);
            Assert.AreEqual("DNS Belgium vzw/asbl", result.TechContact.Organization);
            Assert.AreEqual("+32 16 28 49 70", result.TechContact.TelephoneNumber);
            Assert.AreEqual("whois.dns.be", result.Url);
        }

        [Test]
        public void TestLookupNotFound()
        {
            var response = reader.Read("whois.iana.org", "tld", "not_assigned.txt");
            TcpReaderFactory.Bind(() => new FakeTcpReader(response));

            var result = lookup.Lookup("test.be");

            Assert.IsNotNull(result);
            Assert.AreEqual("eh", result.Tld);
            Assert.AreEqual(WhoisResponseStatus.NotAssigned, result.Status);
        }
    }
}
