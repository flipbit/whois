using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iana.Org.Int
{
    public class IntParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public IntParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.iana.org", "int", "not_found.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.iana.org/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.int", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.iana.org", "int", "found.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.iana.org/Found01", response.TemplateName);

            Assert.Equal("nato.int", response.DomainName.ToString());

            Assert.Equal(new DateTime(2012, 08, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1997, 08, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("North Atlantic Treaty Organization", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Blvd Leopold III", response.Registrant.Address[0]);
            Assert.Equal("1110 Brussels", response.Registrant.Address[1]);
            Assert.Equal("Brussels", response.Registrant.Address[2]);
            Assert.Equal("Belgium", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("Aidan Murdock", response.AdminContact.Name);
            Assert.Equal("+32 65 44 9168", response.AdminContact.TelephoneNumber);
            Assert.Equal("+32 65 44 9480", response.AdminContact.FaxNumber);
            Assert.Equal("aidan.murdock@ncia.nato.int", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("SHAPE", response.AdminContact.Address[0]);
            Assert.Equal("NCIA SP SDD SAS NAR", response.AdminContact.Address[1]);
            Assert.Equal("Mons Hainaut 7010", response.AdminContact.Address[2]);
            Assert.Equal("Belgium", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("Francesco Conserva", response.TechnicalContact.Name);
            Assert.Equal("+32 65 44 7534", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+32 65 44 7556", response.TechnicalContact.FaxNumber);
            Assert.Equal("francesco.conserva@ncia.nato.int", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("SHAPE", response.TechnicalContact.Address[0]);
            Assert.Equal("NCIA SP SMD ENT EMA", response.TechnicalContact.Address[1]);
            Assert.Equal("Mons Hainaut 7010", response.TechnicalContact.Address[2]);
            Assert.Equal("Belgium", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(7, response.NameServers.Count);
            Assert.Equal("globe.nc3a.nato.int", response.NameServers[0]);
            Assert.Equal("max.nra.nato.int", response.NameServers[1]);
            Assert.Equal("maxima.nra.nato.int", response.NameServers[2]);
            Assert.Equal("ns.namsa.nato.int", response.NameServers[3]);
            Assert.Equal("ns.saclantc.nato.int", response.NameServers[4]);
            Assert.Equal("ns1.cs.ucl.ac.uk", response.NameServers[5]);
            Assert.Equal("ns1.drenet.dnd.ca", response.NameServers[6]);

            Assert.Equal(32, response.FieldsParsed);
        }
    }
}
