using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ua.Ua
{
    public class UaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public UaParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_other_status_clienthold()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found", "oogle.com.ua.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/found/01", response.TemplateName);

            Assert.Equal("oogle.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("ua.imena", response.Registrar.Name);
            Assert.Equal("http://www.imena.ua", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 07, 19, 01, 23, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 07, 18, 12, 15, 39, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 07, 18, 12, 15, 38, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("pl-imena-1", response.Registrant.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.Registrant.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.Registrant.Organization);
            Assert.Equal("+380.442010102", response.Registrant.TelephoneNumber);
            Assert.Equal("+380.442010100", response.Registrant.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Gaidara st. 50", response.Registrant.Address[0]);
            Assert.Equal("KYIV", response.Registrant.Address[1]);
            Assert.Equal("UA", response.Registrant.Address[2]);
            Assert.Equal("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("pl-imena-1", response.AdminContact.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.AdminContact.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.AdminContact.Organization);
            Assert.Equal("+380.442010102", response.AdminContact.TelephoneNumber);
            Assert.Equal("+380.442010100", response.AdminContact.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Gaidara st. 50", response.AdminContact.Address[0]);
            Assert.Equal("KYIV", response.AdminContact.Address[1]);
            Assert.Equal("UA", response.AdminContact.Address[2]);
            Assert.Equal("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("pl-imena-1", response.TechnicalContact.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.TechnicalContact.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.TechnicalContact.Organization);
            Assert.Equal("+380.442010102", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+380.442010100", response.TechnicalContact.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Gaidara st. 50", response.TechnicalContact.Address[0]);
            Assert.Equal("KYIV", response.TechnicalContact.Address[1]);
            Assert.Equal("UA", response.TechnicalContact.Address[2]);
            Assert.Equal("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns3.imena.com.ua", response.NameServers[0]);
            Assert.Equal("ns2.imena.com.ua", response.NameServers[1]);
            Assert.Equal("ns1.imena.com.ua", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("clientHold", response.DomainStatus[0]);

            Assert.Equal(46, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_clienttransferprohibited()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found", "fcbank.com.ua.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/found/01", response.TemplateName);

            Assert.Equal("fcbank.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("ua.register", response.Registrar.Name);
            Assert.Equal("http://register.ua", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 06, 14, 11, 09, 54, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 08, 06, 10, 17, 36, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 08, 06, 10, 17, 36, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("com-fac5-1", response.Registrant.RegistryId);
            Assert.Equal(@"JSC ""Finance and Credit""  Bank", response.Registrant.Name);
            Assert.Equal(@"JSC ""Finance and Credit""  Bank", response.Registrant.Organization);
            Assert.Equal("+380.443642909", response.Registrant.TelephoneNumber);
            Assert.Equal("hostmaster@fcbank.com.ua", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Artema str 60", response.Registrant.Address[0]);
            Assert.Equal("KIEV", response.Registrant.Address[1]);
            Assert.Equal("UA", response.Registrant.Address[2]);
            Assert.Equal("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("com-fac5-1", response.AdminContact.RegistryId);
            Assert.Equal(@"JSC ""Finance and Credit""  Bank", response.AdminContact.Name);
            Assert.Equal(@"JSC ""Finance and Credit""  Bank", response.AdminContact.Organization);
            Assert.Equal("+380.443642909", response.AdminContact.TelephoneNumber);
            Assert.Equal("hostmaster@fcbank.com.ua", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Artema str 60", response.AdminContact.Address[0]);
            Assert.Equal("KIEV", response.AdminContact.Address[1]);
            Assert.Equal("UA", response.AdminContact.Address[2]);
            Assert.Equal("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("com-fac5-1", response.TechnicalContact.RegistryId);
            Assert.Equal(@"JSC ""Finance and Credit""  Bank", response.TechnicalContact.Name);
            Assert.Equal(@"JSC ""Finance and Credit""  Bank", response.TechnicalContact.Organization);
            Assert.Equal("+380.443642909", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("hostmaster@fcbank.com.ua", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Artema str 60", response.TechnicalContact.Address[0]);
            Assert.Equal("KIEV", response.TechnicalContact.Address[1]);
            Assert.Equal("UA", response.TechnicalContact.Address[2]);
            Assert.Equal("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(5, response.NameServers.Count);
            Assert.Equal("ns2.fcbank.com.ua", response.NameServers[0]);
            Assert.Equal("ns1.fcbank.com.ua", response.NameServers[1]);
            Assert.Equal("ns.secondary.net.ua", response.NameServers[2]);
            Assert.Equal("ns1.fcbank.com.ua", response.NameServers[3]);
            Assert.Equal("ns2.fcbank.com.ua", response.NameServers[4]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

            Assert.Equal(45, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found", "other_status_graceperiod.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/found/01", response.TemplateName);

            Assert.Equal("oogle.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("ua.imena", response.Registrar.Name);
            Assert.Equal("http://www.imena.ua", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 07, 19, 01, 23, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 07, 18, 12, 15, 39, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 07, 18, 12, 15, 38, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("pl-imena-1", response.Registrant.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.Registrant.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.Registrant.Organization);
            Assert.Equal("+380.442010102", response.Registrant.TelephoneNumber);
            Assert.Equal("+380.442010100", response.Registrant.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Gaidara st. 50", response.Registrant.Address[0]);
            Assert.Equal("KYIV", response.Registrant.Address[1]);
            Assert.Equal("UA", response.Registrant.Address[2]);
            Assert.Equal("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("pl-imena-1", response.AdminContact.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.AdminContact.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.AdminContact.Organization);
            Assert.Equal("+380.442010102", response.AdminContact.TelephoneNumber);
            Assert.Equal("+380.442010100", response.AdminContact.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Gaidara st. 50", response.AdminContact.Address[0]);
            Assert.Equal("KYIV", response.AdminContact.Address[1]);
            Assert.Equal("UA", response.AdminContact.Address[2]);
            Assert.Equal("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("pl-imena-1", response.TechnicalContact.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.TechnicalContact.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.TechnicalContact.Organization);
            Assert.Equal("+380.442010102", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+380.442010100", response.TechnicalContact.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Gaidara st. 50", response.TechnicalContact.Address[0]);
            Assert.Equal("KYIV", response.TechnicalContact.Address[1]);
            Assert.Equal("UA", response.TechnicalContact.Address[2]);
            Assert.Equal("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns3.imena.com.ua", response.NameServers[0]);
            Assert.Equal("ns2.imena.com.ua", response.NameServers[1]);
            Assert.Equal("ns1.imena.com.ua", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("AutoRenewGracePeriod", response.DomainStatus[0]);

            Assert.Equal(46, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found", "google.com.ua.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/found/01", response.TemplateName);

            Assert.Equal("google.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("ua.imena", response.Registrar.Name);
            Assert.Equal("http://www.imena.ua", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 04, 15, 17, 00, 10, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2002, 12, 03, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 12, 03, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("com-gi8-1", response.Registrant.RegistryId);
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+16503300100", response.Registrant.TelephoneNumber);
            Assert.Equal("+16506188571", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway Mountain View CA 94043 US", response.Registrant.Address[0]);
            Assert.Equal("n/a", response.Registrant.Address[1]);
            Assert.Equal("UA", response.Registrant.Address[2]);
            Assert.Equal("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("com-gi8-1", response.AdminContact.RegistryId);
            Assert.Equal("Google Inc.", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+16503300100", response.AdminContact.TelephoneNumber);
            Assert.Equal("+16506188571", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway Mountain View CA 94043 US", response.AdminContact.Address[0]);
            Assert.Equal("n/a", response.AdminContact.Address[1]);
            Assert.Equal("UA", response.AdminContact.Address[2]);
            Assert.Equal("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("com-gi8-1", response.TechnicalContact.RegistryId);
            Assert.Equal("Google Inc.", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+16503300100", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+16506188571", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway Mountain View CA 94043 US", response.TechnicalContact.Address[0]);
            Assert.Equal("n/a", response.TechnicalContact.Address[1]);
            Assert.Equal("UA", response.TechnicalContact.Address[2]);
            Assert.Equal("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns3.google.com", response.NameServers[0]);
            Assert.Equal("ns1.google.com", response.NameServers[1]);
            Assert.Equal("ns4.google.com", response.NameServers[2]);
            Assert.Equal("ns2.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(47, response.FieldsParsed);
        }

        [Fact]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "pending-delete", "pending_delete.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.PendingDelete, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/found/01", response.TemplateName);

            Assert.Equal("googke.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("ua.imena", response.Registrar.Name);
            Assert.Equal("http://www.imena.ua", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 06, 03, 20, 33, 01, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 04, 05, 14, 53, 25, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 04, 05, 14, 53, 25, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("pl-imena-1", response.Registrant.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.Registrant.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.Registrant.Organization);
            Assert.Equal("+380.442010102", response.Registrant.TelephoneNumber);
            Assert.Equal("+380.442010100", response.Registrant.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Gaidara st. 50", response.Registrant.Address[0]);
            Assert.Equal("KYIV", response.Registrant.Address[1]);
            Assert.Equal("UA", response.Registrant.Address[2]);
            Assert.Equal("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("pl-imena-1", response.AdminContact.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.AdminContact.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.AdminContact.Organization);
            Assert.Equal("+380.442010102", response.AdminContact.TelephoneNumber);
            Assert.Equal("+380.442010100", response.AdminContact.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Gaidara st. 50", response.AdminContact.Address[0]);
            Assert.Equal("KYIV", response.AdminContact.Address[1]);
            Assert.Equal("UA", response.AdminContact.Address[2]);
            Assert.Equal("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("pl-imena-1", response.TechnicalContact.RegistryId);
            Assert.Equal(@"""Internet Invest"" Ltd", response.TechnicalContact.Name);
            Assert.Equal(@"""Internet Invest"" Ltd", response.TechnicalContact.Organization);
            Assert.Equal("+380.442010102", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+380.442010100", response.TechnicalContact.FaxNumber);
            Assert.Equal("hostmaster@imena.ua", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Gaidara st. 50", response.TechnicalContact.Address[0]);
            Assert.Equal("KYIV", response.TechnicalContact.Address[1]);
            Assert.Equal("UA", response.TechnicalContact.Address[2]);
            Assert.Equal("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns3.imena.com.ua", response.NameServers[0]);
            Assert.Equal("ns2.imena.com.ua", response.NameServers[1]);
            Assert.Equal("ns1.imena.com.ua", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("pendingDelete", response.DomainStatus[0]);

            Assert.Equal(46, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_redemptionperiod()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found", "other_status_redemptionperiod.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Redemption, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/found/01", response.TemplateName);

            Assert.Equal("googlw.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("ua.freehost", response.Registrar.Name);
            Assert.Equal("http://www.freehost.ua", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 07, 18, 21, 01, 45, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2012, 06, 19, 07, 13, 30, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 06, 19, 07, 13, 30, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("frh-qrlkjdef1llb", response.Registrant.RegistryId);
            Assert.Equal("not published", response.Registrant.Name);
            Assert.Equal("KOT-studiya", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(1, response.Registrant.Address.Count);
            Assert.Equal("n/a", response.Registrant.Address[0]);


             // AdminContact Details
            Assert.Equal("frh-clwxo1st7ewr", response.AdminContact.RegistryId);
            Assert.Equal("not published", response.AdminContact.Name);
            Assert.Equal("KOT-studiya", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("n/a", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("frh-hsa3zl8hqqso", response.TechnicalContact.RegistryId);
            Assert.Equal("not published", response.TechnicalContact.Name);
            Assert.Equal("KOT-studiya", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("n/a", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.notpaid.com.ua", response.NameServers[0]);
            Assert.Equal("ns1.notpaid.com.ua", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("RedemptionPeriod", response.DomainStatus[0]);

            Assert.Equal(27, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "not-found", "u34jedzcq.com.ua.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.com.ua", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found", "kyivstar.ua.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/found/02", response.TemplateName);

            Assert.Equal("kyivstar.ua", response.DomainName.ToString());


             // AdminContact Details
            Assert.Equal("KG780-UANIC", response.AdminContact.RegistryId);
            Assert.Equal("Kyivstar GSM", response.AdminContact.Organization);
            Assert.Equal("+380 (44) 2473939", response.AdminContact.TelephoneNumber);
            Assert.Equal("+380 (44) 2473954", response.AdminContact.FaxNumber);
            Assert.Equal("dnsmaster@kyivstar.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("Chervonozoryanyi Av., 51", response.AdminContact.Address[0]);
            Assert.Equal("03110 KYIV", response.AdminContact.Address[1]);
            Assert.Equal("UA", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("KG780-UANIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Kyivstar GSM", response.TechnicalContact.Organization);
            Assert.Equal("+380 (44) 2473939", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+380 (44) 2473954", response.TechnicalContact.FaxNumber);
            Assert.Equal("dnsmaster@kyivstar.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("Chervonozoryanyi Av., 51", response.TechnicalContact.Address[0]);
            Assert.Equal("03110 KYIV", response.TechnicalContact.Address[1]);
            Assert.Equal("UA", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.elvisti.kiev.ua", response.NameServers[0]);
            Assert.Equal("ns.kyivstar.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("OK-UNTIL 20140903121852", response.DomainStatus[0]);

            Assert.Equal(35, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_contacts_multiple()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found", "found_contacts_multiple.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ua/ua/found/02", response.TemplateName);

            Assert.Equal("kyivstar.ua", response.DomainName.ToString());


             // AdminContact Details
            Assert.Equal("KG780-UANIC", response.AdminContact.RegistryId);
            Assert.Equal("Kyivstar GSM", response.AdminContact.Organization);
            Assert.Equal("+380 (44) 2473939", response.AdminContact.TelephoneNumber);
            Assert.Equal("+380 (44) 2473954", response.AdminContact.FaxNumber);
            Assert.Equal("dnsmaster@kyivstar.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("Chervonozoryanyi Av., 51", response.AdminContact.Address[0]);
            Assert.Equal("03110 KYIV", response.AdminContact.Address[1]);
            Assert.Equal("UA", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("KG780-UANIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Kyivstar GSM", response.TechnicalContact.Organization);
            Assert.Equal("+380 (44) 2473939", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+380 (44) 2473954", response.TechnicalContact.FaxNumber);
            Assert.Equal("dnsmaster@kyivstar.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("Chervonozoryanyi Av., 51", response.TechnicalContact.Address[0]);
            Assert.Equal("03110 KYIV", response.TechnicalContact.Address[1]);
            Assert.Equal("UA", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.elvisti.kiev.ua", response.NameServers[0]);
            Assert.Equal("ns.kyivstar.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("OK-UNTIL 20140903121852", response.DomainStatus[0]);

            Assert.Equal(35, response.FieldsParsed);
        }
    }
}
