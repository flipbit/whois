using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Eu.Org.EuOrg
{
    public class EuOrgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public EuOrgParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.eu.org", "eu.org", "not-found", "not_found.txt");
            var response = parser.Parse("whois.eu.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.eu.org/eu.org/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.eu.org", "eu.org", "found", "google.eu.org.txt");
            var response = parser.Parse("whois.eu.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/03", response.TemplateName);

            Assert.Equal("google.eu.org", response.DomainName.ToString());

            Assert.Equal(new DateTime(2003, 03, 27, 23, 00, 00, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.Equal("Mueller Michael", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Wilhelm-Busch-Str. 35", response.Registrant.Address[0]);
            Assert.Equal("32108 Bad Salzuflen", response.Registrant.Address[1]);
            Assert.Equal("Germany", response.Registrant.Address[2]);

             // AdminContact Details
            Assert.Equal("MM114-FREE", response.AdminContact.RegistryId);
            Assert.Equal("Mueller Michael", response.AdminContact.Name);
            Assert.Equal("+49 005222 94569", response.AdminContact.TelephoneNumber);
            Assert.Equal("mm114-d7ea0ef920c90b777acb325103212a7c@handles.eu.org", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("Wilhelm-Busch-Str. 35", response.AdminContact.Address[0]);
            Assert.Equal("32108 Bad Salzuflen", response.AdminContact.Address[1]);
            Assert.Equal("Germany", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("MM114-FREE", response.TechnicalContact.RegistryId);
            Assert.Equal("Mueller Michael", response.TechnicalContact.Name);
            Assert.Equal("+49 005222 94569", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("mm114-d7ea0ef920c90b777acb325103212a7c@handles.eu.org", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("Wilhelm-Busch-Str. 35", response.TechnicalContact.Address[0]);
            Assert.Equal("32108 Bad Salzuflen", response.TechnicalContact.Address[1]);
            Assert.Equal("Germany", response.TechnicalContact.Address[2]);

            Assert.Equal(16, response.FieldsParsed);
        }
    }
}
