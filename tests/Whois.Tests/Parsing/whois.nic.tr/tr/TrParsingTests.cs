using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tr.Tr
{
    [TestFixture]
    public class TrParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Found", response.TemplateName);

            Assert.AreEqual(new DateTime(2001, 08, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 08, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("+ 1-650-2530000-", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+ 1-650-2530001-", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View CA", response.Registrant.Address[1]);
            Assert.AreEqual("United States of America", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("mi154-metu", response.AdminContact.RegistryId);
            Assert.AreEqual("MarkMonitor, Inc", response.AdminContact.Organization);


             // BillingContact Details
            Assert.AreEqual("btl1-metu", response.BillingContact.RegistryId);
            Assert.AreEqual("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.AreEqual("+ 90-312-4733035-", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+ 90-312-4733039-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.BillingContact.Address[0]);
            Assert.AreEqual("No:114 G-4 Balgat", response.BillingContact.Address[1]);
            Assert.AreEqual("Ankara,06520", response.BillingContact.Address[2]);
            Assert.AreEqual("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("btl1-metu", response.TechnicalContact.RegistryId);
            Assert.AreEqual("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.AreEqual("+ 90-312-4733035-", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+ 90-312-4733039-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.TechnicalContact.Address[0]);
            Assert.AreEqual("No:114 G-4 Balgat", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ankara,06520", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(32, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_person()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_contact_person.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.AreEqual(new DateTime(2009, 11, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 11, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Sevdin Filiz", response.Registrant.Name);
            Assert.AreEqual("+ 90-212-6116571-", response.Registrant.TelephoneNumber);
            Assert.AreEqual("phpbb@canver.net", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Çýnar mh. 10.sok", response.Registrant.Address[0]);
            Assert.AreEqual("Ýstanbul,", response.Registrant.Address[1]);
            Assert.AreEqual("Türkiye", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("sf256-metu", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.AreEqual("sf256-metu", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("sf256-metu", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.phpsunucu.com", response.NameServers[0]);
            Assert.AreEqual("ns2.phpsunucu.com", response.NameServers[1]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.AreEqual(new DateTime(2004, 03, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 03, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("RH RADORE HOSTING INTERNET HÝZMETLERÝ TÝC. LTD. ÞTÝ.", response.Registrant.Name);
            Assert.AreEqual("+ 90-212-3479932-", response.Registrant.TelephoneNumber);
            Assert.AreEqual("kubilay@akyol.info", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Ataturk Sanayi Sitesi 1. Kýsým A Blok No:128", response.Registrant.Address[0]);
            Assert.AreEqual("Maslak", response.Registrant.Address[1]);
            Assert.AreEqual("Ýstanbul,", response.Registrant.Address[2]);
            Assert.AreEqual("Türkiye", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("rrh2-metu", response.AdminContact.RegistryId);
            Assert.AreEqual("RH RADORE HOSTING INTERNET HÝZMETLERÝ TÝC. LTD. ÞTÝ.", response.AdminContact.Organization);
            Assert.AreEqual("+ 90-212-3440404-", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+ 90-212-3440009-", response.AdminContact.FaxNumber);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Büyükdere Cad. No:171 Metrocity AVM 4B. D.39-46S", response.AdminContact.Address[0]);
            Assert.AreEqual("Levent", response.AdminContact.Address[1]);
            Assert.AreEqual("Ýstanbul,34394", response.AdminContact.Address[2]);
            Assert.AreEqual("Türkiye", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("rrh2-metu", response.BillingContact.RegistryId);
            Assert.AreEqual("RH RADORE HOSTING INTERNET HÝZMETLERÝ TÝC. LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.AreEqual("+ 90-212-3440404-", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+ 90-212-3440009-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Büyükdere Cad. No:171 Metrocity AVM 4B. D.39-46S", response.BillingContact.Address[0]);
            Assert.AreEqual("Levent", response.BillingContact.Address[1]);
            Assert.AreEqual("Ýstanbul,34394", response.BillingContact.Address[2]);
            Assert.AreEqual("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("rrh2-metu", response.TechnicalContact.RegistryId);
            Assert.AreEqual("RH RADORE HOSTING INTERNET HÝZMETLERÝ TÝC. LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.AreEqual("+ 90-212-3440404-", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+ 90-212-3440009-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Büyükdere Cad. No:171 Metrocity AVM 4B. D.39-46S", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Levent", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ýstanbul,34394", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("titan.radore.com", response.NameServers[0]);
            Assert.AreEqual("janus.radore.com", response.NameServers[1]);

            Assert.AreEqual(36, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_with_trailing_space()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_nameservers_with_trailing_space.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Found", response.TemplateName);

            Assert.AreEqual(new DateTime(2009, 11, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 11, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Sevdin Filiz", response.Registrant.Name);
            Assert.AreEqual("+ 90-212-6116571-", response.Registrant.TelephoneNumber);
            Assert.AreEqual("phpbb@canver.net", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Çýnar mh. 10.sok", response.Registrant.Address[0]);
            Assert.AreEqual("Ýstanbul,", response.Registrant.Address[1]);
            Assert.AreEqual("Türkiye", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("sf256-metu", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.AreEqual("sf256-metu", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("sf256-metu", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.phpsunucu.com", response.NameServers[0]);
            Assert.AreEqual("ns2.phpsunucu.com", response.NameServers[1]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_found_registrant_contact_outside_cityinoneline()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_outside_cityinoneline.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.AreEqual(new DateTime(1998, 09, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 09, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Yahoo Ýnc.", response.Registrant.Name);
            Assert.AreEqual("+ 901-408-3493300-", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+ 901-408-3493301", response.Registrant.FaxNumber);
            Assert.AreEqual("domainadmin@yahoo-inc.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("701 First Avenue Sunnyvale Ca 94089", response.Registrant.Address[0]);
            Assert.AreEqual("Out of Turkey,", response.Registrant.Address[1]);
            Assert.AreEqual("United States of America", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("mi154-metu", response.AdminContact.RegistryId);
            Assert.AreEqual("MarkMonitor, Inc", response.AdminContact.Organization);


             // BillingContact Details
            Assert.AreEqual("btl1-metu", response.BillingContact.RegistryId);
            Assert.AreEqual("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.AreEqual("+ 90-312-4733035-", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+ 90-312-4733039-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.BillingContact.Address[0]);
            Assert.AreEqual("No:114 G-4 Balgat", response.BillingContact.Address[1]);
            Assert.AreEqual("Ankara,06520", response.BillingContact.Address[2]);
            Assert.AreEqual("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("btl1-metu", response.TechnicalContact.RegistryId);
            Assert.AreEqual("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.AreEqual("+ 90-312-4733035-", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+ 90-312-4733039-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.TechnicalContact.Address[0]);
            Assert.AreEqual("No:114 G-4 Balgat", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ankara,06520", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.yahoo.com", response.NameServers[0]);
            Assert.AreEqual("ns5.yahoo.com", response.NameServers[1]);

            Assert.AreEqual(30, response.FieldsParsed);
        }

        [Test]
        public void Test_found_registrant_contact_outside_citynextline()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_outside_citynextline.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.AreEqual(new DateTime(2001, 08, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 08, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("+ 1-650-2530000-", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+ 1-650-2530001-", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View CA", response.Registrant.Address[1]);
            Assert.AreEqual("United States of America", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("mi154-metu", response.AdminContact.RegistryId);
            Assert.AreEqual("MarkMonitor, Inc", response.AdminContact.Organization);


             // BillingContact Details
            Assert.AreEqual("btl1-metu", response.BillingContact.RegistryId);
            Assert.AreEqual("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.AreEqual("+ 90-312-4733035-", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+ 90-312-4733039-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.BillingContact.Address[0]);
            Assert.AreEqual("No:114 G-4 Balgat", response.BillingContact.Address[1]);
            Assert.AreEqual("Ankara,06520", response.BillingContact.Address[2]);
            Assert.AreEqual("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("btl1-metu", response.TechnicalContact.RegistryId);
            Assert.AreEqual("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.AreEqual("+ 90-312-4733035-", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+ 90-312-4733039-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.TechnicalContact.Address[0]);
            Assert.AreEqual("No:114 G-4 Balgat", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ankara,06520", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(32, response.FieldsParsed);
        }

        [Test]
        public void Test_found_registrant_contact_turkey()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_turkey.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.AreEqual(new DateTime(2004, 06, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 06, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Hotel Bilgisayar Hizmetleri San. Tic. Turizm Ltd. Þti.", response.Registrant.Name);
            Assert.AreEqual("+ 90-212-2473997-", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+ 90-212-2473995", response.Registrant.FaxNumber);
            Assert.AreEqual("romeo6860@yahoo.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Cumhuriyet Cd. No:61 Bingül Han Asma Kat", response.Registrant.Address[0]);
            Assert.AreEqual("Elmadað", response.Registrant.Address[1]);
            Assert.AreEqual("Ýstanbul,", response.Registrant.Address[2]);
            Assert.AreEqual("Türkiye", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("hbh18-metu", response.AdminContact.RegistryId);
            Assert.AreEqual("Hotel Bilgisayar Hizmetleri San.Tic.Tur.Ltd.Sti", response.AdminContact.Organization);
            Assert.AreEqual("+ 90-212-2473997-", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+ 90-212-2473995-", response.AdminContact.FaxNumber);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Cumhuriyet.cad.No:61 Bingul han asma kat", response.AdminContact.Address[0]);
            Assert.AreEqual("Elmada-ISTANBUL", response.AdminContact.Address[1]);
            Assert.AreEqual("Ýstanbul,", response.AdminContact.Address[2]);
            Assert.AreEqual("Türkiye", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("hbh18-metu", response.BillingContact.RegistryId);
            Assert.AreEqual("Hotel Bilgisayar Hizmetleri San.Tic.Tur.Ltd.Sti", response.BillingContact.Organization);
            Assert.AreEqual("+ 90-212-2473997-", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+ 90-212-2473995-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Cumhuriyet.cad.No:61 Bingul han asma kat", response.BillingContact.Address[0]);
            Assert.AreEqual("Elmada-ISTANBUL", response.BillingContact.Address[1]);
            Assert.AreEqual("Ýstanbul,", response.BillingContact.Address[2]);
            Assert.AreEqual("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("hbh18-metu", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Hotel Bilgisayar Hizmetleri San.Tic.Tur.Ltd.Sti", response.TechnicalContact.Organization);
            Assert.AreEqual("+ 90-212-2473997-", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+ 90-212-2473995-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Cumhuriyet.cad.No:61 Bingul han asma kat", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Elmada-ISTANBUL", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ýstanbul,", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Türkiye", response.TechnicalContact.Address[3]);


            Assert.AreEqual(35, response.FieldsParsed);
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "error.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Error, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Error", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "not_found.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.com.tr", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "invalid.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Error, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Error", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tr/tr/Found", response.TemplateName);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("+ 1-650-2530000-", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+ 1-650-2530001-", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View CA", response.Registrant.Address[1]);
            Assert.AreEqual("United States of America", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("mi154-metu", response.AdminContact.RegistryId);
            Assert.AreEqual("MarkMonitor, Inc", response.AdminContact.Organization);


             // BillingContact Details
            Assert.AreEqual("btl1-metu", response.BillingContact.RegistryId);
            Assert.AreEqual("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.AreEqual("+ 90-312-4733035-", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+ 90-312-4733039-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.BillingContact.Address[0]);
            Assert.AreEqual("No:114 G-4 Balgat", response.BillingContact.Address[1]);
            Assert.AreEqual("Ankara,06520", response.BillingContact.Address[2]);
            Assert.AreEqual("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("btl1-metu", response.TechnicalContact.RegistryId);
            Assert.AreEqual("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.AreEqual("+ 90-312-4733035-", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+ 90-312-4733039-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.TechnicalContact.Address[0]);
            Assert.AreEqual("No:114 G-4 Balgat", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ankara,06520", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(32, response.FieldsParsed);
        }
    }
}
