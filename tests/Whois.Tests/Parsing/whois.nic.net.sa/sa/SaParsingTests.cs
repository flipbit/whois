using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Net.Sa.Sa
{
    public class SaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public SaParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.net.sa", "sa", "not-found", "u34jedzcq.com.sa.txt");
            var response = parser.Parse("whois.nic.net.sa", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.net.sa/sa/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.com.sa", response.DomainName.ToString());


            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.net.sa", "sa", "found", "saudigazette.com.sa.txt");
            var response = parser.Parse("whois.nic.net.sa", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.net.sa/sa/found/01", response.TemplateName);

            Assert.Equal("saudigazette.com.sa", response.DomainName.ToString());

            Assert.Equal(new DateTime(2000, 09, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2000, 09, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Okaz for Press and Publication مؤسسة عكاظ للصحافة والنشر", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("~noAddress  P.O.Box. 1508 ص.ب.", response.Registrant.Address[0]);
            Assert.Equal("21441 Jeddah جدة", response.Registrant.Address[1]);
            Assert.Equal("Saudi Arabia المملكة العربية السعودية", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("Abdullah Salmeem Ba-Doukhn عبد الله سالمين بادخن (ADM-837-AD59-SA)", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("حي الرحاب  P.O.Box. 1508 ص.ب.", response.AdminContact.Address[0]);
            Assert.Equal("21441 Jeddah جدة", response.AdminContact.Address[1]);
            Assert.Equal("Saudi Arabia المملكة العربية السعودية", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("Salim Ba-wafi سالم باوافي (TEC-837-SW13-SA)", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("حي الرحاب  P.O.Box. 1508 ص.ب.", response.TechnicalContact.Address[0]);
            Assert.Equal("21441 Jeddah جدة", response.TechnicalContact.Address[1]);
            Assert.Equal("Saudi Arabia المملكة العربية السعودية", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.peer1.net", response.NameServers[0]);
            Assert.Equal("ns2.peer1.net", response.NameServers[1]);

            Assert.Equal(18, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);
        }
    }
}
