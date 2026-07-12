using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Net.Sb.Sb
{
    public class SbParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public SbParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.net.sb", "sb", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.net.sb", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/05", response.TemplateName);

            Assert.Equal("u34jedzcq.sb", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.net.sb", "sb", "found", "found.txt");
            var response = parser.Parse("whois.nic.net.sb", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("baidu.com.sb", response.DomainName.ToString());
            Assert.Equal("404765-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Key-Systems", response.Registrar.Name);
            Assert.Equal("http://www.key-systems.net", response.Registrar.Url);
            Assert.Equal("info@key-systems.net", response.Registrar.AbuseEmail);
            Assert.Equal("+49 (0)68949396850", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2012, 02, 26, 05, 08, 41, 045, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 03, 27, 04, 29, 19, 249, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 03, 27, 04, 29, 19, 346, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("419751-CoCCA", response.Registrant.RegistryId);
            Assert.Equal("long dian", response.Registrant.Name);
            Assert.Equal("999.cn.vc", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("shannxi", response.Registrant.Address[0]);
            Assert.Equal("xian", response.Registrant.Address[1]);
            Assert.Equal("710000", response.Registrant.Address[2]);
            Assert.Equal("CN", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("419751-CoCCA", response.AdminContact.RegistryId);
            Assert.Equal("long dian", response.AdminContact.Name);
            Assert.Equal("999.cn.vc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("shannxi", response.AdminContact.Address[0]);
            Assert.Equal("xian", response.AdminContact.Address[1]);
            Assert.Equal("710000", response.AdminContact.Address[2]);
            Assert.Equal("CN", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("419751-CoCCA", response.BillingContact.RegistryId);
            Assert.Equal("long dian", response.BillingContact.Name);
            Assert.Equal("999.cn.vc", response.BillingContact.Organization);
            Assert.Equal("+1.123456789", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.123456789", response.BillingContact.FaxNumber);
            Assert.Equal("hostcn@gmail.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("shannxi", response.BillingContact.Address[0]);
            Assert.Equal("xian", response.BillingContact.Address[1]);
            Assert.Equal("710000", response.BillingContact.Address[2]);
            Assert.Equal("CN", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("419751-CoCCA", response.TechnicalContact.RegistryId);
            Assert.Equal("long dian", response.TechnicalContact.Name);
            Assert.Equal("999.cn.vc", response.TechnicalContact.Organization);
            Assert.Equal("+1.123456789", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.123456789", response.TechnicalContact.FaxNumber);
            Assert.Equal("hostcn@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("shannxi", response.TechnicalContact.Address[0]);
            Assert.Equal("xian", response.TechnicalContact.Address[1]);
            Assert.Equal("710000", response.TechnicalContact.Address[2]);
            Assert.Equal("CN", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("f1g1ns1.dnspod.net", response.NameServers[0]);
            Assert.Equal("f1g1ns2.dnspod.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(48, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.net.sb", "sb", "not-found", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.net.sb", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/05", response.TemplateName);

            Assert.Equal("u34jedzcq.sb", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.net.sb", "sb", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.net.sb", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("baidu.com.sb", response.DomainName.ToString());
            Assert.Equal("404765-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Key-Systems", response.Registrar.Name);
            Assert.Equal("http://www.key-systems.net", response.Registrar.Url);
            Assert.Equal("info@key-systems.net", response.Registrar.AbuseEmail);
            Assert.Equal("+49 (0)68949396850", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2012, 02, 26, 05, 08, 41, 045, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 03, 27, 04, 29, 19, 249, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 03, 27, 04, 29, 19, 346, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("419751-CoCCA", response.Registrant.RegistryId);
            Assert.Equal("long dian", response.Registrant.Name);
            Assert.Equal("999.cn.vc", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("shannxi", response.Registrant.Address[0]);
            Assert.Equal("xian", response.Registrant.Address[1]);
            Assert.Equal("710000", response.Registrant.Address[2]);
            Assert.Equal("CN", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("419751-CoCCA", response.AdminContact.RegistryId);
            Assert.Equal("long dian", response.AdminContact.Name);
            Assert.Equal("999.cn.vc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("shannxi", response.AdminContact.Address[0]);
            Assert.Equal("xian", response.AdminContact.Address[1]);
            Assert.Equal("710000", response.AdminContact.Address[2]);
            Assert.Equal("CN", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("419751-CoCCA", response.BillingContact.RegistryId);
            Assert.Equal("long dian", response.BillingContact.Name);
            Assert.Equal("999.cn.vc", response.BillingContact.Organization);
            Assert.Equal("+1.123456789", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.123456789", response.BillingContact.FaxNumber);
            Assert.Equal("hostcn@gmail.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("shannxi", response.BillingContact.Address[0]);
            Assert.Equal("xian", response.BillingContact.Address[1]);
            Assert.Equal("710000", response.BillingContact.Address[2]);
            Assert.Equal("CN", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("419751-CoCCA", response.TechnicalContact.RegistryId);
            Assert.Equal("long dian", response.TechnicalContact.Name);
            Assert.Equal("999.cn.vc", response.TechnicalContact.Organization);
            Assert.Equal("+1.123456789", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.123456789", response.TechnicalContact.FaxNumber);
            Assert.Equal("hostcn@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("shannxi", response.TechnicalContact.Address[0]);
            Assert.Equal("xian", response.TechnicalContact.Address[1]);
            Assert.Equal("710000", response.TechnicalContact.Address[2]);
            Assert.Equal("CN", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("f1g1ns1.dnspod.net", response.NameServers[0]);
            Assert.Equal("f1g1ns2.dnspod.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(48, response.FieldsParsed);
        }
    }
}
