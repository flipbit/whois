using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tr.Tr
{
    public class TrParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public TrParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Found", response.TemplateName);

            Assert.Equal(new DateTime(2001, 08, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 08, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("+ 1-650-2530000-", response.Registrant.TelephoneNumber);
            Assert.Equal("+ 1-650-2530001-", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View CA", response.Registrant.Address[1]);
            Assert.Equal("United States of America", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("mi154-metu", response.AdminContact.RegistryId);
            Assert.Equal("MarkMonitor, Inc", response.AdminContact.Organization);


             // BillingContact Details
            Assert.Equal("btl1-metu", response.BillingContact.RegistryId);
            Assert.Equal("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.Equal("+ 90-312-4733035-", response.BillingContact.TelephoneNumber);
            Assert.Equal("+ 90-312-4733039-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.BillingContact.Address[0]);
            Assert.Equal("No:114 G-4 Balgat", response.BillingContact.Address[1]);
            Assert.Equal("Ankara,06520", response.BillingContact.Address[2]);
            Assert.Equal("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("btl1-metu", response.TechnicalContact.RegistryId);
            Assert.Equal("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.Equal("+ 90-312-4733035-", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+ 90-312-4733039-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.TechnicalContact.Address[0]);
            Assert.Equal("No:114 G-4 Balgat", response.TechnicalContact.Address[1]);
            Assert.Equal("Ankara,06520", response.TechnicalContact.Address[2]);
            Assert.Equal("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(32, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_contact_person()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_contact_person.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.Equal(new DateTime(2009, 11, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 11, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Sevdin Filiz", response.Registrant.Name);
            Assert.Equal("+ 90-212-6116571-", response.Registrant.TelephoneNumber);
            Assert.Equal("phpbb@canver.net", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Çýnar mh. 10.sok", response.Registrant.Address[0]);
            Assert.Equal("Ýstanbul,", response.Registrant.Address[1]);
            Assert.Equal("Türkiye", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("sf256-metu", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.Equal("sf256-metu", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.Equal("sf256-metu", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.phpsunucu.com", response.NameServers[0]);
            Assert.Equal("ns2.phpsunucu.com", response.NameServers[1]);

            Assert.Equal(14, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.Equal(new DateTime(2004, 03, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 03, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("RH RADORE HOSTING INTERNET HÝZMETLERÝ TÝC. LTD. ÞTÝ.", response.Registrant.Name);
            Assert.Equal("+ 90-212-3479932-", response.Registrant.TelephoneNumber);
            Assert.Equal("kubilay@akyol.info", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Ataturk Sanayi Sitesi 1. Kýsým A Blok No:128", response.Registrant.Address[0]);
            Assert.Equal("Maslak", response.Registrant.Address[1]);
            Assert.Equal("Ýstanbul,", response.Registrant.Address[2]);
            Assert.Equal("Türkiye", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("rrh2-metu", response.AdminContact.RegistryId);
            Assert.Equal("RH RADORE HOSTING INTERNET HÝZMETLERÝ TÝC. LTD. ÞTÝ.", response.AdminContact.Organization);
            Assert.Equal("+ 90-212-3440404-", response.AdminContact.TelephoneNumber);
            Assert.Equal("+ 90-212-3440009-", response.AdminContact.FaxNumber);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Büyükdere Cad. No:171 Metrocity AVM 4B. D.39-46S", response.AdminContact.Address[0]);
            Assert.Equal("Levent", response.AdminContact.Address[1]);
            Assert.Equal("Ýstanbul,34394", response.AdminContact.Address[2]);
            Assert.Equal("Türkiye", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("rrh2-metu", response.BillingContact.RegistryId);
            Assert.Equal("RH RADORE HOSTING INTERNET HÝZMETLERÝ TÝC. LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.Equal("+ 90-212-3440404-", response.BillingContact.TelephoneNumber);
            Assert.Equal("+ 90-212-3440009-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Büyükdere Cad. No:171 Metrocity AVM 4B. D.39-46S", response.BillingContact.Address[0]);
            Assert.Equal("Levent", response.BillingContact.Address[1]);
            Assert.Equal("Ýstanbul,34394", response.BillingContact.Address[2]);
            Assert.Equal("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("rrh2-metu", response.TechnicalContact.RegistryId);
            Assert.Equal("RH RADORE HOSTING INTERNET HÝZMETLERÝ TÝC. LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.Equal("+ 90-212-3440404-", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+ 90-212-3440009-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Büyükdere Cad. No:171 Metrocity AVM 4B. D.39-46S", response.TechnicalContact.Address[0]);
            Assert.Equal("Levent", response.TechnicalContact.Address[1]);
            Assert.Equal("Ýstanbul,34394", response.TechnicalContact.Address[2]);
            Assert.Equal("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("titan.radore.com", response.NameServers[0]);
            Assert.Equal("janus.radore.com", response.NameServers[1]);

            Assert.Equal(36, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_nameservers_with_trailing_space()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_nameservers_with_trailing_space.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Found", response.TemplateName);

            Assert.Equal(new DateTime(2009, 11, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 11, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Sevdin Filiz", response.Registrant.Name);
            Assert.Equal("+ 90-212-6116571-", response.Registrant.TelephoneNumber);
            Assert.Equal("phpbb@canver.net", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Çýnar mh. 10.sok", response.Registrant.Address[0]);
            Assert.Equal("Ýstanbul,", response.Registrant.Address[1]);
            Assert.Equal("Türkiye", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("sf256-metu", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.Equal("sf256-metu", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.Equal("sf256-metu", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.phpsunucu.com", response.NameServers[0]);
            Assert.Equal("ns2.phpsunucu.com", response.NameServers[1]);

            Assert.Equal(14, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_registrant_contact_outside_cityinoneline()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_outside_cityinoneline.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.Equal(new DateTime(1998, 09, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 09, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Yahoo Ýnc.", response.Registrant.Name);
            Assert.Equal("+ 901-408-3493300-", response.Registrant.TelephoneNumber);
            Assert.Equal("+ 901-408-3493301", response.Registrant.FaxNumber);
            Assert.Equal("domainadmin@yahoo-inc.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("701 First Avenue Sunnyvale Ca 94089", response.Registrant.Address[0]);
            Assert.Equal("Out of Turkey,", response.Registrant.Address[1]);
            Assert.Equal("United States of America", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("mi154-metu", response.AdminContact.RegistryId);
            Assert.Equal("MarkMonitor, Inc", response.AdminContact.Organization);


             // BillingContact Details
            Assert.Equal("btl1-metu", response.BillingContact.RegistryId);
            Assert.Equal("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.Equal("+ 90-312-4733035-", response.BillingContact.TelephoneNumber);
            Assert.Equal("+ 90-312-4733039-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.BillingContact.Address[0]);
            Assert.Equal("No:114 G-4 Balgat", response.BillingContact.Address[1]);
            Assert.Equal("Ankara,06520", response.BillingContact.Address[2]);
            Assert.Equal("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("btl1-metu", response.TechnicalContact.RegistryId);
            Assert.Equal("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.Equal("+ 90-312-4733035-", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+ 90-312-4733039-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.TechnicalContact.Address[0]);
            Assert.Equal("No:114 G-4 Balgat", response.TechnicalContact.Address[1]);
            Assert.Equal("Ankara,06520", response.TechnicalContact.Address[2]);
            Assert.Equal("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.yahoo.com", response.NameServers[0]);
            Assert.Equal("ns5.yahoo.com", response.NameServers[1]);

            Assert.Equal(30, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_registrant_contact_outside_citynextline()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_outside_citynextline.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.Equal(new DateTime(2001, 08, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 08, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("+ 1-650-2530000-", response.Registrant.TelephoneNumber);
            Assert.Equal("+ 1-650-2530001-", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View CA", response.Registrant.Address[1]);
            Assert.Equal("United States of America", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("mi154-metu", response.AdminContact.RegistryId);
            Assert.Equal("MarkMonitor, Inc", response.AdminContact.Organization);


             // BillingContact Details
            Assert.Equal("btl1-metu", response.BillingContact.RegistryId);
            Assert.Equal("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.Equal("+ 90-312-4733035-", response.BillingContact.TelephoneNumber);
            Assert.Equal("+ 90-312-4733039-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.BillingContact.Address[0]);
            Assert.Equal("No:114 G-4 Balgat", response.BillingContact.Address[1]);
            Assert.Equal("Ankara,06520", response.BillingContact.Address[2]);
            Assert.Equal("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("btl1-metu", response.TechnicalContact.RegistryId);
            Assert.Equal("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.Equal("+ 90-312-4733035-", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+ 90-312-4733039-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.TechnicalContact.Address[0]);
            Assert.Equal("No:114 G-4 Balgat", response.TechnicalContact.Address[1]);
            Assert.Equal("Ankara,06520", response.TechnicalContact.Address[2]);
            Assert.Equal("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(32, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_registrant_contact_turkey()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_turkey.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Found", response.TemplateName);


            Assert.Equal(new DateTime(2004, 06, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 06, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Hotel Bilgisayar Hizmetleri San. Tic. Turizm Ltd. Þti.", response.Registrant.Name);
            Assert.Equal("+ 90-212-2473997-", response.Registrant.TelephoneNumber);
            Assert.Equal("+ 90-212-2473995", response.Registrant.FaxNumber);
            Assert.Equal("romeo6860@yahoo.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Cumhuriyet Cd. No:61 Bingül Han Asma Kat", response.Registrant.Address[0]);
            Assert.Equal("Elmadað", response.Registrant.Address[1]);
            Assert.Equal("Ýstanbul,", response.Registrant.Address[2]);
            Assert.Equal("Türkiye", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("hbh18-metu", response.AdminContact.RegistryId);
            Assert.Equal("Hotel Bilgisayar Hizmetleri San.Tic.Tur.Ltd.Sti", response.AdminContact.Organization);
            Assert.Equal("+ 90-212-2473997-", response.AdminContact.TelephoneNumber);
            Assert.Equal("+ 90-212-2473995-", response.AdminContact.FaxNumber);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Cumhuriyet.cad.No:61 Bingul han asma kat", response.AdminContact.Address[0]);
            Assert.Equal("Elmada-ISTANBUL", response.AdminContact.Address[1]);
            Assert.Equal("Ýstanbul,", response.AdminContact.Address[2]);
            Assert.Equal("Türkiye", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("hbh18-metu", response.BillingContact.RegistryId);
            Assert.Equal("Hotel Bilgisayar Hizmetleri San.Tic.Tur.Ltd.Sti", response.BillingContact.Organization);
            Assert.Equal("+ 90-212-2473997-", response.BillingContact.TelephoneNumber);
            Assert.Equal("+ 90-212-2473995-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Cumhuriyet.cad.No:61 Bingul han asma kat", response.BillingContact.Address[0]);
            Assert.Equal("Elmada-ISTANBUL", response.BillingContact.Address[1]);
            Assert.Equal("Ýstanbul,", response.BillingContact.Address[2]);
            Assert.Equal("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("hbh18-metu", response.TechnicalContact.RegistryId);
            Assert.Equal("Hotel Bilgisayar Hizmetleri San.Tic.Tur.Ltd.Sti", response.TechnicalContact.Organization);
            Assert.Equal("+ 90-212-2473997-", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+ 90-212-2473995-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Cumhuriyet.cad.No:61 Bingul han asma kat", response.TechnicalContact.Address[0]);
            Assert.Equal("Elmada-ISTANBUL", response.TechnicalContact.Address[1]);
            Assert.Equal("Ýstanbul,", response.TechnicalContact.Address[2]);
            Assert.Equal("Türkiye", response.TechnicalContact.Address[3]);


            Assert.Equal(35, response.FieldsParsed);
        }

        [Fact]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "error.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Error, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Error", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "not_found.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.com.tr", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "invalid.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Error, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Error", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.tr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.tr/tr/Found", response.TemplateName);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("+ 1-650-2530000-", response.Registrant.TelephoneNumber);
            Assert.Equal("+ 1-650-2530001-", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View CA", response.Registrant.Address[1]);
            Assert.Equal("United States of America", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("mi154-metu", response.AdminContact.RegistryId);
            Assert.Equal("MarkMonitor, Inc", response.AdminContact.Organization);


             // BillingContact Details
            Assert.Equal("btl1-metu", response.BillingContact.RegistryId);
            Assert.Equal("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.BillingContact.Organization);
            Assert.Equal("+ 90-312-4733035-", response.BillingContact.TelephoneNumber);
            Assert.Equal("+ 90-312-4733039-", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.BillingContact.Address[0]);
            Assert.Equal("No:114 G-4 Balgat", response.BillingContact.Address[1]);
            Assert.Equal("Ankara,06520", response.BillingContact.Address[2]);
            Assert.Equal("Türkiye", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("btl1-metu", response.TechnicalContact.RegistryId);
            Assert.Equal("BERÝL TEKNOLOJÝ LTD. ÞTÝ.", response.TechnicalContact.Organization);
            Assert.Equal("+ 90-312-4733035-", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+ 90-312-4733039-", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Ceyhun Atuf Kansu Cad. Bayraktar Ýþ Merkezi", response.TechnicalContact.Address[0]);
            Assert.Equal("No:114 G-4 Balgat", response.TechnicalContact.Address[1]);
            Assert.Equal("Ankara,06520", response.TechnicalContact.Address[2]);
            Assert.Equal("Türkiye", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(32, response.FieldsParsed);
        }
    }
}
