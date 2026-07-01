using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ua.Ua
{
    [TestFixture]
    public class UaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_clienthold()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "other_status_clienthold.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/Found01", response.TemplateName);

            Assert.AreEqual("oogle.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("ua.imena", response.Registrar.Name);
            Assert.AreEqual("http://www.imena.ua", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 07, 19, 01, 23, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 07, 18, 12, 15, 39, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 07, 18, 12, 15, 38, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("pl-imena-1", response.Registrant.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.Registrant.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.Registrant.Organization);
            Assert.AreEqual("+380.442010102", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.Registrant.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.Registrant.Address[0]);
            Assert.AreEqual("KYIV", response.Registrant.Address[1]);
            Assert.AreEqual("UA", response.Registrant.Address[2]);
            Assert.AreEqual("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("pl-imena-1", response.AdminContact.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.AdminContact.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.AdminContact.Organization);
            Assert.AreEqual("+380.442010102", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.AdminContact.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.AdminContact.Address[0]);
            Assert.AreEqual("KYIV", response.AdminContact.Address[1]);
            Assert.AreEqual("UA", response.AdminContact.Address[2]);
            Assert.AreEqual("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("pl-imena-1", response.TechnicalContact.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.TechnicalContact.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.TechnicalContact.Organization);
            Assert.AreEqual("+380.442010102", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.TechnicalContact.Address[0]);
            Assert.AreEqual("KYIV", response.TechnicalContact.Address[1]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns3.imena.com.ua", response.NameServers[0]);
            Assert.AreEqual("ns2.imena.com.ua", response.NameServers[1]);
            Assert.AreEqual("ns1.imena.com.ua", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("clientHold", response.DomainStatus[0]);

            Assert.AreEqual(46, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_clienttransferprohibited()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "other_status_clienttransferprohibited.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/Found01", response.TemplateName);

            Assert.AreEqual("fcbank.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("ua.register", response.Registrar.Name);
            Assert.AreEqual("http://register.ua", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 06, 14, 11, 09, 54, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 08, 06, 10, 17, 36, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 08, 06, 10, 17, 36, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("com-fac5-1", response.Registrant.RegistryId);
            Assert.AreEqual(@"JSC ""Finance and Credit""  Bank", response.Registrant.Name);
            Assert.AreEqual(@"JSC ""Finance and Credit""  Bank", response.Registrant.Organization);
            Assert.AreEqual("+380.443642909", response.Registrant.TelephoneNumber);
            Assert.AreEqual("hostmaster@fcbank.com.ua", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Artema str 60", response.Registrant.Address[0]);
            Assert.AreEqual("KIEV", response.Registrant.Address[1]);
            Assert.AreEqual("UA", response.Registrant.Address[2]);
            Assert.AreEqual("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("com-fac5-1", response.AdminContact.RegistryId);
            Assert.AreEqual(@"JSC ""Finance and Credit""  Bank", response.AdminContact.Name);
            Assert.AreEqual(@"JSC ""Finance and Credit""  Bank", response.AdminContact.Organization);
            Assert.AreEqual("+380.443642909", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@fcbank.com.ua", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Artema str 60", response.AdminContact.Address[0]);
            Assert.AreEqual("KIEV", response.AdminContact.Address[1]);
            Assert.AreEqual("UA", response.AdminContact.Address[2]);
            Assert.AreEqual("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("com-fac5-1", response.TechnicalContact.RegistryId);
            Assert.AreEqual(@"JSC ""Finance and Credit""  Bank", response.TechnicalContact.Name);
            Assert.AreEqual(@"JSC ""Finance and Credit""  Bank", response.TechnicalContact.Organization);
            Assert.AreEqual("+380.443642909", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@fcbank.com.ua", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Artema str 60", response.TechnicalContact.Address[0]);
            Assert.AreEqual("KIEV", response.TechnicalContact.Address[1]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("ns2.fcbank.com.ua", response.NameServers[0]);
            Assert.AreEqual("ns1.fcbank.com.ua", response.NameServers[1]);
            Assert.AreEqual("ns.secondary.net.ua", response.NameServers[2]);
            Assert.AreEqual("ns1.fcbank.com.ua", response.NameServers[3]);
            Assert.AreEqual("ns2.fcbank.com.ua", response.NameServers[4]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);

            Assert.AreEqual(45, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "other_status_graceperiod.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/Found01", response.TemplateName);

            Assert.AreEqual("oogle.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("ua.imena", response.Registrar.Name);
            Assert.AreEqual("http://www.imena.ua", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 07, 19, 01, 23, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 07, 18, 12, 15, 39, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 07, 18, 12, 15, 38, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("pl-imena-1", response.Registrant.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.Registrant.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.Registrant.Organization);
            Assert.AreEqual("+380.442010102", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.Registrant.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.Registrant.Address[0]);
            Assert.AreEqual("KYIV", response.Registrant.Address[1]);
            Assert.AreEqual("UA", response.Registrant.Address[2]);
            Assert.AreEqual("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("pl-imena-1", response.AdminContact.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.AdminContact.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.AdminContact.Organization);
            Assert.AreEqual("+380.442010102", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.AdminContact.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.AdminContact.Address[0]);
            Assert.AreEqual("KYIV", response.AdminContact.Address[1]);
            Assert.AreEqual("UA", response.AdminContact.Address[2]);
            Assert.AreEqual("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("pl-imena-1", response.TechnicalContact.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.TechnicalContact.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.TechnicalContact.Organization);
            Assert.AreEqual("+380.442010102", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.TechnicalContact.Address[0]);
            Assert.AreEqual("KYIV", response.TechnicalContact.Address[1]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns3.imena.com.ua", response.NameServers[0]);
            Assert.AreEqual("ns2.imena.com.ua", response.NameServers[1]);
            Assert.AreEqual("ns1.imena.com.ua", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("AutoRenewGracePeriod", response.DomainStatus[0]);

            Assert.AreEqual(46, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/Found01", response.TemplateName);

            Assert.AreEqual("google.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("ua.imena", response.Registrar.Name);
            Assert.AreEqual("http://www.imena.ua", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 04, 15, 17, 00, 10, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 12, 03, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 12, 03, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("com-gi8-1", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+16503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+16506188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway Mountain View CA 94043 US", response.Registrant.Address[0]);
            Assert.AreEqual("n/a", response.Registrant.Address[1]);
            Assert.AreEqual("UA", response.Registrant.Address[2]);
            Assert.AreEqual("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("com-gi8-1", response.AdminContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+16503300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+16506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway Mountain View CA 94043 US", response.AdminContact.Address[0]);
            Assert.AreEqual("n/a", response.AdminContact.Address[1]);
            Assert.AreEqual("UA", response.AdminContact.Address[2]);
            Assert.AreEqual("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("com-gi8-1", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+16503300100", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+16506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway Mountain View CA 94043 US", response.TechnicalContact.Address[0]);
            Assert.AreEqual("n/a", response.TechnicalContact.Address[1]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns3.google.com", response.NameServers[0]);
            Assert.AreEqual("ns1.google.com", response.NameServers[1]);
            Assert.AreEqual("ns4.google.com", response.NameServers[2]);
            Assert.AreEqual("ns2.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(47, response.FieldsParsed);
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "pending_delete.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/Found01", response.TemplateName);

            Assert.AreEqual("googke.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("ua.imena", response.Registrar.Name);
            Assert.AreEqual("http://www.imena.ua", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 06, 03, 20, 33, 01, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 04, 05, 14, 53, 25, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 04, 05, 14, 53, 25, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("pl-imena-1", response.Registrant.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.Registrant.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.Registrant.Organization);
            Assert.AreEqual("+380.442010102", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.Registrant.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.Registrant.Address[0]);
            Assert.AreEqual("KYIV", response.Registrant.Address[1]);
            Assert.AreEqual("UA", response.Registrant.Address[2]);
            Assert.AreEqual("UA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("pl-imena-1", response.AdminContact.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.AdminContact.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.AdminContact.Organization);
            Assert.AreEqual("+380.442010102", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.AdminContact.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.AdminContact.Address[0]);
            Assert.AreEqual("KYIV", response.AdminContact.Address[1]);
            Assert.AreEqual("UA", response.AdminContact.Address[2]);
            Assert.AreEqual("UA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("pl-imena-1", response.TechnicalContact.RegistryId);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.TechnicalContact.Name);
            Assert.AreEqual(@"""Internet Invest"" Ltd", response.TechnicalContact.Organization);
            Assert.AreEqual("+380.442010102", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+380.442010100", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("hostmaster@imena.ua", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Gaidara st. 50", response.TechnicalContact.Address[0]);
            Assert.AreEqual("KYIV", response.TechnicalContact.Address[1]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns3.imena.com.ua", response.NameServers[0]);
            Assert.AreEqual("ns2.imena.com.ua", response.NameServers[1]);
            Assert.AreEqual("ns1.imena.com.ua", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pendingDelete", response.DomainStatus[0]);

            Assert.AreEqual(46, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_redemptionperiod()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "other_status_redemptionperiod.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Redemption, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/Found01", response.TemplateName);

            Assert.AreEqual("googlw.com.ua", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("ua.freehost", response.Registrar.Name);
            Assert.AreEqual("http://www.freehost.ua", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 07, 18, 21, 01, 45, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2012, 06, 19, 07, 13, 30, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 06, 19, 07, 13, 30, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("frh-qrlkjdef1llb", response.Registrant.RegistryId);
            Assert.AreEqual("not published", response.Registrant.Name);
            Assert.AreEqual("KOT-studiya", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("n/a", response.Registrant.Address[0]);


             // AdminContact Details
            Assert.AreEqual("frh-clwxo1st7ewr", response.AdminContact.RegistryId);
            Assert.AreEqual("not published", response.AdminContact.Name);
            Assert.AreEqual("KOT-studiya", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("n/a", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("frh-hsa3zl8hqqso", response.TechnicalContact.RegistryId);
            Assert.AreEqual("not published", response.TechnicalContact.Name);
            Assert.AreEqual("KOT-studiya", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("n/a", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.notpaid.com.ua", response.NameServers[0]);
            Assert.AreEqual("ns1.notpaid.com.ua", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("RedemptionPeriod", response.DomainStatus[0]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "not_found.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.com.ua", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found_status_registered.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/Found02", response.TemplateName);

            Assert.AreEqual("kyivstar.ua", response.DomainName.ToString());


             // AdminContact Details
            Assert.AreEqual("KG780-UANIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Kyivstar GSM", response.AdminContact.Organization);
            Assert.AreEqual("+380 (44) 2473939", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+380 (44) 2473954", response.AdminContact.FaxNumber);
            Assert.AreEqual("dnsmaster@kyivstar.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Chervonozoryanyi Av., 51", response.AdminContact.Address[0]);
            Assert.AreEqual("03110 KYIV", response.AdminContact.Address[1]);
            Assert.AreEqual("UA", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("KG780-UANIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Kyivstar GSM", response.TechnicalContact.Organization);
            Assert.AreEqual("+380 (44) 2473939", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+380 (44) 2473954", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dnsmaster@kyivstar.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Chervonozoryanyi Av., 51", response.TechnicalContact.Address[0]);
            Assert.AreEqual("03110 KYIV", response.TechnicalContact.Address[1]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.elvisti.kiev.ua", response.NameServers[0]);
            Assert.AreEqual("ns.kyivstar.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK-UNTIL 20140903121852", response.DomainStatus[0]);

            Assert.AreEqual(35, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contacts_multiple()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found_contacts_multiple.txt");
            var response = parser.Parse("whois.ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ua/ua/Found02", response.TemplateName);

            Assert.AreEqual("kyivstar.ua", response.DomainName.ToString());


             // AdminContact Details
            Assert.AreEqual("KG780-UANIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Kyivstar GSM", response.AdminContact.Organization);
            Assert.AreEqual("+380 (44) 2473939", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+380 (44) 2473954", response.AdminContact.FaxNumber);
            Assert.AreEqual("dnsmaster@kyivstar.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Chervonozoryanyi Av., 51", response.AdminContact.Address[0]);
            Assert.AreEqual("03110 KYIV", response.AdminContact.Address[1]);
            Assert.AreEqual("UA", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("KG780-UANIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Kyivstar GSM", response.TechnicalContact.Organization);
            Assert.AreEqual("+380 (44) 2473939", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+380 (44) 2473954", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dnsmaster@kyivstar.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Chervonozoryanyi Av., 51", response.TechnicalContact.Address[0]);
            Assert.AreEqual("03110 KYIV", response.TechnicalContact.Address[1]);
            Assert.AreEqual("UA", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.elvisti.kiev.ua", response.NameServers[0]);
            Assert.AreEqual("ns.kyivstar.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK-UNTIL 20140903121852", response.DomainStatus[0]);

            Assert.AreEqual(35, response.FieldsParsed);
        }
    }
}
