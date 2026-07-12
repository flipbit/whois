using Xunit;
using System;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Bnnic.Bn.Bn
{
    public class BnParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public BnParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.bnnic.bn", "bn", "not-found", "not_found.txt");
            var response = parser.Parse("whois.bnnic.bn", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/02", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.bnnic.bn", "bn", "found", "found.txt");
            var response = parser.Parse("whois.bnnic.bn", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(11, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.bnnic.bn/bn/found/01", response.TemplateName);

            Assert.Equal("telbru.com.bn", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("TELEKOM BRUNEI BERHAD", response.Registrar.Name);

            Assert.Equal(new DateTime(2014, 12, 17, 18, 7, 42), response.Updated);
            Assert.Equal(new DateTime(2014, 10, 7, 0, 0, 0), response.Registered);
            Assert.Equal(new DateTime(2015, 10, 7, 0, 0, 0), response.Expiration);

            // Registrant Details
            Assert.Equal("BruNet| Telekom Brunei Berhad - (BNC875T)", response.Registrant.Name);

             // AdminContact Details
            Assert.Equal("BruNet| Telekom Brunei Berhad - (BNC875T)", response.AdminContact.Name);

             // TechnicalContact Details
            Assert.Equal("BruNet| Telekom Brunei Berhad - (BNC875T)", response.TechnicalContact.Name);
            Assert.Equal("info@telbru.com.bn", response.TechnicalContact.Email);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);
        }
    }
}
