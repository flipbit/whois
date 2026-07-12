using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Priv.At.At
{
    public class AtParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AtParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.priv.at", "at", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.priv.at", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.priv.at/at/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.priv.at", "at", "found", "nic.priv.at.txt");
            var response = parser.Parse("whois.nic.priv.at", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.priv.at/at/found/01", response.TemplateName);

            Assert.Equal("nic.priv.at", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Network Information Center for priv.at", response.Registrar.Name);
            Assert.Equal("hostmaster@nic.priv.at", response.Registrar.AbuseEmail);

            Assert.Equal(new DateTime(2002, 10, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.Equal("HM-PRIVAT", response.AdminContact.RegistryId);
            Assert.Equal("Hostmaster priv.at", response.AdminContact.Name);
            Assert.Equal("hostmaster@nic.priv.at", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("Verein fuer Internet-Benutzer Oesterreichs (VIBE!AT)", response.AdminContact.Address[0]);
            Assert.Equal("c/o Gerald Pfeifer", response.AdminContact.Address[1]);
            Assert.Equal("Mondweg 64", response.AdminContact.Address[2]);
            Assert.Equal("A-1140", response.AdminContact.Address[3]);
            Assert.Equal("Wien", response.AdminContact.Address[4]);
            Assert.Equal("Austria", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("HM-PRIVAT", response.TechnicalContact.RegistryId);
            Assert.Equal("Hostmaster priv.at", response.TechnicalContact.Name);
            Assert.Equal("hostmaster@nic.priv.at", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("Verein fuer Internet-Benutzer Oesterreichs (VIBE!AT)", response.TechnicalContact.Address[0]);
            Assert.Equal("c/o Gerald Pfeifer", response.TechnicalContact.Address[1]);
            Assert.Equal("Mondweg 64", response.TechnicalContact.Address[2]);
            Assert.Equal("A-1140", response.TechnicalContact.Address[3]);
            Assert.Equal("Wien", response.TechnicalContact.Address[4]);
            Assert.Equal("Austria", response.TechnicalContact.Address[5]);


             // ZoneContact Details
            Assert.Equal("HM-PRIVAT", response.ZoneContact.RegistryId);
            Assert.Equal("Hostmaster priv.at", response.ZoneContact.Name);
            Assert.Equal("hostmaster@nic.priv.at", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.Equal(6, response.ZoneContact.Address.Count);
            Assert.Equal("Verein fuer Internet-Benutzer Oesterreichs (VIBE!AT)", response.ZoneContact.Address[0]);
            Assert.Equal("c/o Gerald Pfeifer", response.ZoneContact.Address[1]);
            Assert.Equal("Mondweg 64", response.ZoneContact.Address[2]);
            Assert.Equal("A-1140", response.ZoneContact.Address[3]);
            Assert.Equal("Wien", response.ZoneContact.Address[4]);
            Assert.Equal("Austria", response.ZoneContact.Address[5]);


            Assert.Equal(17, response.FieldsParsed);
        }
    }
}
