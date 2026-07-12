using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.DeCom
{
    public class DeComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public DeComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "de.com", "not-found", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "de.com", "found", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

            Assert.Equal("autopoint.de.com", response.DomainName.ToString());
            Assert.Equal("CNIC-DO578833", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("united-domains AG", response.Registrar.Name);
            Assert.Equal("http://www.united-domains.de", response.Registrar.Url);
            Assert.Equal("+498151368670", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 7, 12, 10, 3, 56, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 7, 4, 20, 30, 8, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 7, 4, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("H1102323", response.Registrant.RegistryId);
            Assert.Equal("Stefan Von Gehlen", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Muelgaustr. 292-294, Moenchengladbach", response.Registrant.Address[0]);
            Assert.Equal("41238", response.Registrant.Address[1]);
            Assert.Equal("DE", response.Registrant.Address[2]);

            Assert.Equal("+49.2166120626", response.Registrant.TelephoneNumber);
            Assert.Equal("s.vongehlen@arcor.de", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("H402505", response.AdminContact.RegistryId);
            Assert.Equal("Stefan Von Gehlen", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("Muelgaustr. 292-294, Moenchengladbach", response.AdminContact.Address[0]);
            Assert.Equal("41238", response.AdminContact.Address[1]);
            Assert.Equal("DE", response.AdminContact.Address[2]);

            Assert.Equal("+49.2166120626", response.AdminContact.TelephoneNumber);
            Assert.Equal("s.vongehlen@arcor.de", response.AdminContact.Email);


             // BillingContact Details
            Assert.Equal("C-UHM65D7-TJGULR", response.BillingContact.RegistryId);
            Assert.Equal("Host Master", response.BillingContact.Name);
            Assert.Equal("united-domains AG", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("Gautinger Str. 10", response.BillingContact.Address[0]);
            Assert.Equal("Starnberg", response.BillingContact.Address[1]);
            Assert.Equal("Bayern", response.BillingContact.Address[2]);
            Assert.Equal("82319", response.BillingContact.Address[3]);
            Assert.Equal("DE", response.BillingContact.Address[4]);

            Assert.Equal("+49.8151368670", response.BillingContact.TelephoneNumber);
            Assert.Equal("+49.81513686777", response.BillingContact.FaxNumber);
            Assert.Equal("hostmaster@united-domains.de", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("C-UHM65D7-TJGULR", response.TechnicalContact.RegistryId);
            Assert.Equal("Host Master", response.TechnicalContact.Name);
            Assert.Equal("united-domains AG", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Gautinger Str. 10", response.TechnicalContact.Address[0]);
            Assert.Equal("Starnberg", response.TechnicalContact.Address[1]);
            Assert.Equal("Bayern", response.TechnicalContact.Address[2]);
            Assert.Equal("82319", response.TechnicalContact.Address[3]);
            Assert.Equal("DE", response.TechnicalContact.Address[4]);

            Assert.Equal("+49.8151368670", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("hostmaster@united-domains.de", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns.udagdns.net", response.NameServers[0]);
            Assert.Equal("ns.udagdns.de", response.NameServers[1]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(50, response.FieldsParsed);
        }
    }
}
