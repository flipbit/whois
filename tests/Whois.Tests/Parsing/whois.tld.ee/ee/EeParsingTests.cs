using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tld.Ee.Ee
{
    public class EeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public EeParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_other_status_serverhold()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "found", "other_status_serverhold.txt");
            var response = parser.Parse("whois.tld.ee", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Expired, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.tld.ee/ee/found/01", response.TemplateName);

            Assert.Equal("samanacrafts.ee", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Edicy OÜ", response.Registrar.Name);
            Assert.Equal("http://www.edicy.com", response.Registrar.Url);
            Assert.Equal("+3727460064", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 11, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Anastassia Hisamova", response.Registrant.Name);
            Assert.Equal(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.Registrant.Updated);


             // AdminContact Details
            Assert.Equal("Anastassia Hisamova", response.AdminContact.Name);
            Assert.Equal(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.AdminContact.Updated);


             // TechnicalContact Details
            Assert.Equal(new DateTime(2014, 11, 01, 18, 38, 55, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);


            // Nameservers
            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("ns4.edicy.net", response.NameServers[0]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("expired", response.DomainStatus[0]);
            Assert.Equal("serverHold", response.DomainStatus[1]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "not-found", "not_found.txt");
            var response = parser.Parse("whois.tld.ee", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/03", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_expired()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "expired", "expired.txt");
            var response = parser.Parse("whois.tld.ee", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Expired, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.tld.ee/ee/found/01", response.TemplateName);

            Assert.Equal("eestiinternet.ee", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Elisa Eesti AS", response.Registrar.Name);
            Assert.Equal("http://www.elisa.ee", response.Registrar.Url);
            Assert.Equal("+372 660 0600", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2010, 11, 29, 11, 32, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 07, 04, 04, 52, 56, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 11, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Eesti Interneti Sihtasutus", response.Registrant.Name);
            Assert.Equal(new DateTime(2010, 11, 29, 11, 32, 16, 000, DateTimeKind.Utc), response.Registrant.Updated);


             // AdminContact Details
            Assert.Equal("Jaana Järve", response.AdminContact.Name);
            Assert.Equal(new DateTime(2015, 10, 30, 06, 31, 21, 000, DateTimeKind.Utc), response.AdminContact.Updated);


             // TechnicalContact Details
            Assert.Equal("Jaana Järve", response.TechnicalContact.Name);
            Assert.Equal(new DateTime(2015, 10, 30, 06, 31, 21, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);


            // Nameservers
            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("c.tld.ee", response.NameServers[0]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("expired", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "found", "internet.ee.txt");
            var response = parser.Parse("whois.tld.ee", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.tld.ee/ee/found/01", response.TemplateName);

            Assert.Equal("internet.ee", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Elisa Eesti AS", response.Registrar.Name);
            Assert.Equal("http://www.elisa.ee", response.Registrar.Url);
            Assert.Equal("+372 660 0600", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2010, 11, 29, 11, 32, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 08, 10, 13, 43, 38, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2017, 02, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Eesti Interneti Sihtasutus", response.Registrant.Name);
            Assert.Equal(new DateTime(2010, 11, 29, 11, 32, 16, 000, DateTimeKind.Utc), response.Registrant.Updated);


             // AdminContact Details
            Assert.Equal("Jaana Järve", response.AdminContact.Name);
            Assert.Equal(new DateTime(2015, 10, 30, 06, 31, 21, 000, DateTimeKind.Utc), response.AdminContact.Updated);


             // TechnicalContact Details
            Assert.Equal("Jaana Järve", response.TechnicalContact.Name);
            Assert.Equal(new DateTime(2015, 10, 30, 06, 31, 21, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);


            // Nameservers
            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("c.tld.ee", response.NameServers[0]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok (paid and in zone)", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }
    }
}
