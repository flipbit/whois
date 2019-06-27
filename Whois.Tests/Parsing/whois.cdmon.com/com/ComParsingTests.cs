using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cdmon.Com.Com
{
    [TestFixture]
    public class ComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cdmon.com", "com", "found.txt");
            var response = parser.Parse("whois.cdmon.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found02", response.TemplateName);

            Assert.AreEqual("cdmon.com", response.DomainName);

            // Registrar Details
            Assert.AreEqual("10DENCEHISPAHARD, S.L", response.Registrar.Name);
            Assert.AreEqual("https://www.cdmon.com", response.Registrar.Url);
            Assert.AreEqual("whois.cdmon.com", response.Registrar.WhoisServerUrl);
            Assert.AreEqual("abuse@cdmon.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+34.935677577", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2009, 12, 16, 11, 40, 44, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 8, 12, 15, 2, 57, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2024, 8, 12, 15, 2, 53, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("10dencehispahard,s.l.", response.Registrant.Name);
            Assert.AreEqual("10dencehispahard,s.l.", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Girona 81-83 local 6", response.Registrant.Address[0]);
            Assert.AreEqual("Malgrat de Mar", response.Registrant.Address[1]);
            Assert.AreEqual("08380", response.Registrant.Address[2]);
            Assert.AreEqual("ES", response.Registrant.Address[3]);

            Assert.AreEqual("+34.902364138", response.Registrant.TelephoneNumber);
            Assert.AreEqual("info@cdmon.com", response.Registrant.Email);

             // AdminContact Details
            Assert.AreEqual("10dencehispahard,s.l.", response.AdminContact.Name);
            Assert.AreEqual("10dencehispahard,s.l.", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Girona 81-83 local 6", response.AdminContact.Address[0]);
            Assert.AreEqual("Malgrat de Mar", response.AdminContact.Address[1]);
            Assert.AreEqual("08380", response.AdminContact.Address[2]);
            Assert.AreEqual("ES", response.AdminContact.Address[3]);

            Assert.AreEqual("+34.902364138", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("info@cdmon.com", response.AdminContact.Email);

             // TechnicalContact Details
            Assert.AreEqual("10dencehispahard,s.l.", response.TechnicalContact.Name);
            Assert.AreEqual("10dencehispahard,s.l.", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Girona 81-83 local 6", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Malgrat de Mar", response.TechnicalContact.Address[1]);
            Assert.AreEqual("08380", response.TechnicalContact.Address[2]);
            Assert.AreEqual("ES", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+34.902364138", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("info@cdmon.com", response.TechnicalContact.Email);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns2.cdmon.es", response.NameServers[0]);
            Assert.AreEqual("ns3.cdmon.es", response.NameServers[1]);
            Assert.AreEqual("ns1.cdmon.es", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[2]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(42, response.FieldsParsed);
        }
    }
}
