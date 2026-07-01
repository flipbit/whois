using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dot.Tk.Tk
{
    [TestFixture]
    public class TkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dot.tk", "tk", "not_found.txt");
            var response = parser.Parse("whois.dot.tk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dot.tk/tk/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dot.tk", "tk", "found.txt");
            var response = parser.Parse("whois.dot.tk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dot.tk/tk/Found", response.TemplateName);

            Assert.AreEqual("google.tk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2001, 12, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 03, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("eMarkmonitor Inc", response.Registrant.Organization);
            Assert.AreEqual("+1 208-3895740", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1 208-3895799", response.Registrant.FaxNumber);
            Assert.AreEqual("ccopsbilling@markmonitor.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Ccops Center", response.Registrant.Address[0]);
            Assert.AreEqual("PMB 155, 10400 Overland Road", response.Registrant.Address[1]);
            Assert.AreEqual("83709  Boise", response.Registrant.Address[2]);
            Assert.AreEqual("Idaho", response.Registrant.Address[3]);
            Assert.AreEqual("U.S.A.", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
