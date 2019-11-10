using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ax.Ax
{
    [TestFixture]
    public class AxParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.ax", "ax", "not_found.txt");
            var response = parser.Parse("whois.ax", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(2, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ax/ax/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ax", response.DomainName.ToString());
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.ax", "ax", "found.txt");
            var response = parser.Parse("whois.ax", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(11, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ax/ax/Found", response.TemplateName);

            Assert.AreEqual("regeringen.ax", response.DomainName.ToString());


            Assert.AreEqual(new DateTime(2006, 8, 3, 0, 0, 0), response.Registered);
            Assert.AreEqual("Ålands landskapsregering", response.Registrant.Name);
            Assert.AreEqual("0145076-7", response.Registrant.Organization);

            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("AX", response.Registrant.Address[0]);


            Assert.AreEqual("IT-enheten", response.AdminContact.Name);

            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("PB 1060", response.AdminContact.Address[0]);
            Assert.AreEqual("22111  MARIEHAMN", response.AdminContact.Address[1]);

            Assert.AreEqual("itsupport@regeringen.ax", response.AdminContact.Email);


            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("ns.regeringen.ax", response.NameServers[0]);
        }
    }
}
