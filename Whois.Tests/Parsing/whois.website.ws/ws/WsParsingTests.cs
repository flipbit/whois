using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Website.Ws.Ws
{
    [TestFixture]
    public class WsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.website.ws", "ws", "not_found.txt");
            var response = parser.Parse("whois.website.ws", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.website.ws/ws/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ws", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.website.ws", "ws", "found.txt");
            var response = parser.Parse("whois.website.ws", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.website.ws/ws/Found", response.TemplateName);

            Assert.AreEqual("google.ws", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual(".WS Registry", response.Registrar.Name);
            Assert.AreEqual("whois.website.ws", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("support@website.ws", response.Registrar.AbuseEmail);

            Assert.AreEqual(new DateTime(2008, 12, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 03, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 03, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("6503300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("kulpreet@google.com", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(15, response.FieldsParsed);
        }
    }
}
