using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cctld.Uz.Uz
{
    public class UzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public UzParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "reserved", "reserved.txt");
            var response = parser.Parse("whois.cctld.uz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cctld.uz/uz/reserved/01", response.TemplateName);

            Assert.Equal("cctld.uz", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("UZINFOCOM", response.Registrar.Name);
            Assert.Equal("http://www.cctld.uz/", response.Registrar.Url);
            Assert.Equal("www.whois.uz", response.Registrar.WhoisServer.Value);

            Assert.Equal(new DateTime(2005, 5, 1, 0, 0, 0), response.Updated);
            Assert.Equal(new DateTime(2005, 5, 1, 0, 0, 0), response.Registered);

             // Registrant Details
            Assert.Equal("Rakhimov D. K.	(info [at] uzinfocom.uz)", response.Registrant.Name);
            Assert.Equal("not.defined.", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("A.Navoi str., 28 B", response.Registrant.Address[0]);
            Assert.Equal("Tashkent", response.Registrant.Address[1]);
            Assert.Equal("Uzbekistan, 100011", response.Registrant.Address[2]);
            Assert.Equal("UZ", response.Registrant.Address[3]);

            Assert.Equal("+998 71 238-42-00", response.Registrant.TelephoneNumber);
            Assert.Equal("+998 71 238-42-48", response.Registrant.FaxNumber);


             // AdminContact Details
            Assert.Equal("Djuraev I.D.	(info [at] uzinfocom.uz)", response.AdminContact.Name);
            Assert.Equal("Center UZINFOCOM", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("A.Navoi str., 28 B", response.AdminContact.Address[0]);
            Assert.Equal("Tashkent", response.AdminContact.Address[1]);
            Assert.Equal("Uzbekistan, 100011", response.AdminContact.Address[2]);
            Assert.Equal("UZ", response.AdminContact.Address[3]);

            Assert.Equal("+998 71 238-41-48", response.AdminContact.TelephoneNumber);
            Assert.Equal("+998 71 238-42-48", response.AdminContact.FaxNumber);

             // BillingContact Details
            Assert.Equal("Karnaushevskaya A.K.	(info [at] uzinfocom.uz)", response.BillingContact.Name);
            Assert.Equal("Center UZINFOCOM", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("A.Navoi str., 28 B", response.BillingContact.Address[0]);
            Assert.Equal("Tashkent", response.BillingContact.Address[1]);
            Assert.Equal("Uzbekistan, 100011", response.BillingContact.Address[2]);
            Assert.Equal("UZ", response.BillingContact.Address[3]);

            Assert.Equal("+998 71 238-42-00", response.BillingContact.TelephoneNumber);
            Assert.Equal("+998 71 238-42-48", response.BillingContact.FaxNumber);

             // TechnicalContact Details
            Assert.Equal("Deykhin V.V.	(info [at] uzinfocom.uz)", response.TechnicalContact.Name);
            Assert.Equal("Center UZINFOCOM", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("A.Navoi str., 28 B", response.TechnicalContact.Address[0]);
            Assert.Equal("Tashkent", response.TechnicalContact.Address[1]);
            Assert.Equal("Uzbekistan,  100011", response.TechnicalContact.Address[2]);
            Assert.Equal("UZ", response.TechnicalContact.Address[3]);

            Assert.Equal("+998 71 238-42-45", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+998 71 238-42-48", response.TechnicalContact.FaxNumber);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns.uz", response.NameServers[0]);
            Assert.Equal("ns2.uz", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("RESERVED", response.DomainStatus[0]);

            Assert.Equal(42, response.FieldsParsed);
            AssertWriter.Write(response);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "not-found", "not_found.txt");
            var response = parser.Parse("whois.cctld.uz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cctld.uz/uz/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.uz", response.DomainName.ToString());


            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.cctld.uz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cctld.uz/uz/found/01", response.TemplateName);

            Assert.Equal("google.uz", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("TOMAS", response.Registrar.Name);
            Assert.Equal("http://www.cctld.uz/", response.Registrar.Url);
            Assert.Equal("www.whois.uz", response.Registrar.WhoisServer.Value);

            Assert.Equal(new DateTime(2010, 3, 26, 0, 0, 0), response.Updated);
            Assert.Equal(new DateTime(2006, 4, 13, 0, 0, 0), response.Registered);
            Assert.Equal(new DateTime(2011, 5, 1, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.Equal("DNS Admin	(dns-admin [at] google.com)", response.Registrant.Name);
            Assert.Equal("Google Inc", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("2400 E Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("US, 94043", response.Registrant.Address[2]);
            Assert.Equal("US", response.Registrant.Address[3]);

            Assert.Equal("+1 6503300100", response.Registrant.TelephoneNumber);
            Assert.Equal("+1 6506181499", response.Registrant.FaxNumber);

             // AdminContact Details
            Assert.Equal("DNS Admin	(dns-admin [at] google.com)", response.AdminContact.Name);
            Assert.Equal("Google Inc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("2400 E Bayshore Pkwy", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("US, 94043", response.AdminContact.Address[2]);
            Assert.Equal("US", response.AdminContact.Address[3]);

            Assert.Equal("+1 6503300100", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1 6506181499", response.AdminContact.FaxNumber);

             // BillingContact Details
            Assert.Equal("Kevin Pearl	(ccops [at] markmonitor.com)", response.BillingContact.Name);
            Assert.Equal("MarkMonitor", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("10400 Overland Road PMB 155", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("US, 83709", response.BillingContact.Address[2]);
            Assert.Equal("US", response.BillingContact.Address[3]);

            Assert.Equal("+1 208 389 5798", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1 208 389 5771", response.BillingContact.FaxNumber);

             // TechnicalContact Details
            Assert.Equal("DNS Admin	(dns-admin [at] google.com)", response.TechnicalContact.Name);
            Assert.Equal("Google Inc", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("2400 E Bayshore Pkwy", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
            Assert.Equal("US, 94043", response.TechnicalContact.Address[2]);
            Assert.Equal("US", response.TechnicalContact.Address[3]);

            Assert.Equal("+1 6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1 6506181499", response.TechnicalContact.FaxNumber);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(43, response.FieldsParsed);
        }
    }
}
