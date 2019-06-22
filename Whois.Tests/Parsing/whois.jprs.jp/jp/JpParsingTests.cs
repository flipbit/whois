using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.Jp
{
    [TestFixture]
    public class JpParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "suspended.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Suspended, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/jp/Suspended", response.TemplateName);

            Assert.AreEqual("veganwiz.jp", response.DomainName);

            Assert.AreEqual(new DateTime(2012, 8, 1, 0, 29, 53), response.Updated);
            Assert.AreEqual(new DateTime(2010, 7, 7, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2012, 8, 31, 0, 0, 0), response.Expiration);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Suspended", response.DomainStatus[0]);

            Assert.AreEqual(6, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_to_be_suspended()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "other_status_to_be_suspended.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/jp/Other", response.TemplateName);

            Assert.AreEqual("flirtbox.jp", response.DomainName);

            Assert.AreEqual(new DateTime(2011, 12, 21, 18, 30, 48), response.Updated);
            Assert.AreEqual(new DateTime(2003, 12, 9, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2011, 12, 31, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Tobias Marx", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("Tobias Marx", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("166-0002", response.AdminContact.Address[0]);
            Assert.AreEqual("3-43-13 Kouenji-kita Suginami-ku", response.AdminContact.Address[1]);

            Assert.AreEqual("+4915122947636", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("superoverdrive@gmx.de", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.hans.hosteurope.de", response.NameServers[0]);
            Assert.AreEqual("ns2.hans.hosteurope.de", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("To be suspended", response.DomainStatus[0]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "found.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/jp/Found", response.TemplateName);

            Assert.AreEqual("fashionwatch.jp", response.DomainName);

            Assert.AreEqual(new DateTime(2010, 10, 18, 11, 30, 47), response.Updated);
            Assert.AreEqual(new DateTime(2009, 5, 11, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2011, 5, 31, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("coco coco", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("coco coco", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("166-0002", response.AdminContact.Address[0]);
            Assert.AreEqual("3-43-13 Koenji-kita", response.AdminContact.Address[1]);
            Assert.AreEqual("Suginami-ku", response.AdminContact.Address[2]);
            Assert.AreEqual("Tokyo", response.AdminContact.Address[3]);

            Assert.AreEqual("1312748435", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("wld19800720@163.com", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns172.ip-asia.com", response.NameServers[0]);
            Assert.AreEqual("ns171.ip-asia.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "not_found.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/jp/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "found_status_registered.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/jp/Found", response.TemplateName);

            Assert.AreEqual("google.jp", response.DomainName);

            Assert.AreEqual(new DateTime(2013, 6, 1, 1, 5, 7), response.Updated);
            Assert.AreEqual(new DateTime(2005, 5, 30, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2014, 5, 31, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("Google Inc.", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("94043", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);

            Assert.AreEqual("16502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("16502530001", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(19, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "reserved.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/jp/Reserved", response.TemplateName);

            Assert.AreEqual("example.jp", response.DomainName);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Reserved", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found_ameblo_jp()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "ameblo.jp.txt");
            
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/jp/Found", response.TemplateName);

            Assert.AreEqual("ameblo.jp", response.DomainName);

            Assert.AreEqual(new DateTime(2018, 8, 1, 1, 5, 9), response.Updated);
            Assert.AreEqual(new DateTime(2004, 7, 30, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2019, 7, 31, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("CyberAgent, Inc.", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("CyberAgent, Inc.", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("150-0044", response.AdminContact.Address[0]);
            Assert.AreEqual("Shibuya-ku", response.AdminContact.Address[1]);
            Assert.AreEqual("19-1 Maruyamacho", response.AdminContact.Address[2]);
            Assert.AreEqual("Shibuya Prime Plaza 2F", response.AdminContact.Address[3]);

            Assert.AreEqual("03-5459-6150", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("03-5784-7070", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-ssl-info@cyberagent.co.jp", response.AdminContact.Email);

            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("a1-5.akam.net", response.NameServers[0]);
            Assert.AreEqual("a11-66.akam.net", response.NameServers[1]);
            Assert.AreEqual("a20-67.akam.net", response.NameServers[2]);
            Assert.AreEqual("a4-64.akam.net", response.NameServers[3]);
            Assert.AreEqual("a6-65.akam.net", response.NameServers[4]);
            Assert.AreEqual("a7-66.akam.net", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(21, response.FieldsParsed);
        }   
    }
}
