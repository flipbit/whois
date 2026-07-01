using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Educause.Edu.Edu
{
    [TestFixture]
    public class EduParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("nic.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 06, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 12, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("North Idaho College", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1000 W. Garden Avenue", response.Registrant.Address[0]);
            Assert.AreEqual("Coeur d'Alene, ID 83814", response.Registrant.Address[1]);
            Assert.AreEqual("UNITED STATES", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("NetAdmin", response.AdminContact.Name);
            Assert.AreEqual("(208) 769-7860", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("netsys@nic.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("North Idaho College", response.AdminContact.Address[0]);
            Assert.AreEqual("1000 W. Garden Avenue", response.AdminContact.Address[1]);
            Assert.AreEqual("Coeur d Alene, ID 83814", response.AdminContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.AdminContact.Address[3]);

             // TechnicalContact Details
            Assert.AreEqual("Dennis L Noordam", response.TechnicalContact.Name);
            Assert.AreEqual("(208) 769-7860", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dlnoordam@nic.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Windows System Administrator", response.TechnicalContact.Address[0]);
            Assert.AreEqual("North Idaho College", response.TechnicalContact.Address[1]);
            Assert.AreEqual("1000 W. Garden Avenue", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Coeur d Alene, ID 83814", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("nicns1.nic.edu", response.NameServers[0]);
            Assert.AreEqual("nicns2.nic.edu", response.NameServers[1]);

            Assert.AreEqual(26, response.FieldsParsed);
        }

        [Test]
        public void Test_found_fixture2()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture2.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("harvard.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 03, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1985, 06, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Harvard University", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("HUIT Network Services", response.Registrant.Address[0]);
            Assert.AreEqual("60 Oxford Street", response.Registrant.Address[1]);
            Assert.AreEqual("Cambridge, MA 02138", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Jacques N Laflamme", response.AdminContact.Name);
            Assert.AreEqual("(617) 384-6663", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("jacques_laflamme@harvard.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Director, Network Services", response.AdminContact.Address[0]);
            Assert.AreEqual("Harvard University", response.AdminContact.Address[1]);
            Assert.AreEqual("60 Oxford Street", response.AdminContact.Address[2]);
            Assert.AreEqual("Cambridge, MA 02138", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Network Operations", response.TechnicalContact.Name);
            Assert.AreEqual("(617) 495-7777", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("netmanager@harvard.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Harvard University", response.TechnicalContact.Address[0]);
            Assert.AreEqual("HUIT Network Services", response.TechnicalContact.Address[1]);
            Assert.AreEqual("60 Oxford Street", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Cambridge, MA 02138", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("externaldns-c1.harvard.edu", response.NameServers[0]);
            Assert.AreEqual("externaldns-c2.harvard.edu", response.NameServers[1]);
            Assert.AreEqual("externaldns-c3.br.harvard.edu", response.NameServers[2]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_found_fixture3()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture3.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found02", response.TemplateName);

            Assert.AreEqual("stanford.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 05, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1985, 10, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Stanford University", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("The Board of Trustees of the Leland Stanford Junior University", response.Registrant.Address[0]);
            Assert.AreEqual("241 Panama Street, Pine Hall, Room 115", response.Registrant.Address[1]);
            Assert.AreEqual("Stanford, CA 94305-4122", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Domain Admin", response.AdminContact.Name);
            Assert.AreEqual("(650) 723-4328", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("sunet-admin@stanford.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Stanford University", response.AdminContact.Address[0]);
            Assert.AreEqual("241 Panama Street Pine Hall, Room 115", response.AdminContact.Address[1]);
            Assert.AreEqual("Stanford, CA 94305-4122", response.AdminContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Domain Admin", response.TechnicalContact.Name);
            Assert.AreEqual("(650) 723-4328", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("sunet-admin@stanford.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Stanford University", response.TechnicalContact.Address[0]);
            Assert.AreEqual("241 Panama Street Pine Hall, Room 115", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Stanford, CA 94305-4122", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[3]);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("argus.stanford.edu", response.NameServers[0]);
            Assert.AreEqual("avallone.stanford.edu", response.NameServers[1]);
            Assert.AreEqual("atalante.stanford.edu", response.NameServers[2]);
            Assert.AreEqual("aerathea.stanford.edu", response.NameServers[3]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_found_fixture4()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture4.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found02", response.TemplateName);

            Assert.AreEqual("nyu.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2007, 10, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1986, 10, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("New York University", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("ITS Communications Operations Services", response.Registrant.Address[0]);
            Assert.AreEqual("7 East 12th Street, 5th Floor", response.Registrant.Address[1]);
            Assert.AreEqual("New York, NY 10003", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("NYU Network Operations Admin Role Account", response.AdminContact.Name);
            Assert.AreEqual("(212) 998-3431", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("domreg.admin@nyu.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("New York University, ITS C&CS", response.AdminContact.Address[0]);
            Assert.AreEqual("7 East 12th Street", response.AdminContact.Address[1]);
            Assert.AreEqual("5th Floor", response.AdminContact.Address[2]);
            Assert.AreEqual("New York, NY 10003", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Network Operations Center Role Account", response.TechnicalContact.Name);
            Assert.AreEqual("(212) 998-3444", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("noc@nyu.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("New York University, ITS COS", response.TechnicalContact.Address[0]);
            Assert.AreEqual("7 East 12th Street", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Room 501", response.TechnicalContact.Address[2]);
            Assert.AreEqual("New York, NY 10003", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.nyu.edu", response.NameServers[0]);
            Assert.AreEqual("ns2.nyu.edu", response.NameServers[1]);
            Assert.AreEqual("nyu-ns.berkeley.edu", response.NameServers[2]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_found_fixture5()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture5.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("uiuc.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 03, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1985, 07, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("University of Illinois at Urbana Champaign", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("CITES 1120 Digital Computer Laboratory", response.Registrant.Address[0]);
            Assert.AreEqual("1304 West Springfield Avenue", response.Registrant.Address[1]);
            Assert.AreEqual("Urbana, IL 61801-2910", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Tracy L. Smith", response.AdminContact.Name);
            Assert.AreEqual("(217) 244-2032", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("edu-admin@listserv.illinois.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("University of Illinois at Urbana-Champaign", response.AdminContact.Address[0]);
            Assert.AreEqual("CITES  2105 Digital Computer Laboratory", response.AdminContact.Address[1]);
            Assert.AreEqual("1304 West Springfield Avenue", response.AdminContact.Address[2]);
            Assert.AreEqual("Urbana, IL 61801-4399", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Charles Kline", response.TechnicalContact.Name);
            Assert.AreEqual("(217) 333-3339", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("edu-tech@listserv.illinois.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("University of Illinois at Urbana Champaign", response.TechnicalContact.Address[0]);
            Assert.AreEqual("CITES 1120 Digital Computer Laboratory", response.TechnicalContact.Address[1]);
            Assert.AreEqual("1304 West Springfield Avenue", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Urbana, IL 61801", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("dns1.illinois.edu", response.NameServers[0]);
            Assert.AreEqual("dns2.illinois.edu", response.NameServers[1]);
            Assert.AreEqual("dns1.iu.edu", response.NameServers[2]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_found_fixture6()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture6.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found03", response.TemplateName);

            Assert.AreEqual("brown.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 01, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1986, 08, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Brown University", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Computing & Information", response.Registrant.Address[0]);
            Assert.AreEqual("Services Box 1885", response.Registrant.Address[1]);
            Assert.AreEqual("Providence, RI 02912-1885", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Kenise Harris", response.AdminContact.Name);
            Assert.AreEqual("(401) 863-7223", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("kenise_harris@brown.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("CIS Manager", response.AdminContact.Address[0]);
            Assert.AreEqual("Brown University", response.AdminContact.Address[1]);
            Assert.AreEqual("115 Waterman St., Box 1885", response.AdminContact.Address[2]);
            Assert.AreEqual("Providence, RI 02912-1885", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("NOC", response.TechnicalContact.Name);
            Assert.AreEqual("(401) 863-7247", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("noc@brown.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Brown University", response.TechnicalContact.Address[0]);
            Assert.AreEqual("115 Waterman St., Box 1885", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Providence, RI 02912-1885", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("bru-ns1.brown.edu", response.NameServers[0]);
            Assert.AreEqual("bru-ns2.brown.edu", response.NameServers[1]);
            Assert.AreEqual("ns1.ucsb.edu", response.NameServers[2]);

            Assert.AreEqual(26, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contacts()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("nic.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 06, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 12, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("North Idaho College", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1000 W. Garden Avenue", response.Registrant.Address[0]);
            Assert.AreEqual("Coeur d'Alene, ID 83814", response.Registrant.Address[1]);
            Assert.AreEqual("UNITED STATES", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("NetAdmin", response.AdminContact.Name);
            Assert.AreEqual("(208) 769-7860", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("netsys@nic.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("North Idaho College", response.AdminContact.Address[0]);
            Assert.AreEqual("1000 W. Garden Avenue", response.AdminContact.Address[1]);
            Assert.AreEqual("Coeur d Alene, ID 83814", response.AdminContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Dennis L Noordam", response.TechnicalContact.Name);
            Assert.AreEqual("(208) 769-7860", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dlnoordam@nic.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Windows System Administrator", response.TechnicalContact.Address[0]);
            Assert.AreEqual("North Idaho College", response.TechnicalContact.Address[1]);
            Assert.AreEqual("1000 W. Garden Avenue", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Coeur d Alene, ID 83814", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("nicns1.nic.edu", response.NameServers[0]);
            Assert.AreEqual("nicns2.nic.edu", response.NameServers[1]);

            Assert.AreEqual(26, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contacts_case1()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts_case1.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("educause.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 10, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1998, 03, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("EDUCAUSE", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("4772 Walnut Street", response.Registrant.Address[0]);
            Assert.AreEqual("Suite 206", response.Registrant.Address[1]);
            Assert.AreEqual("Boulder, CO 80301", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Information Technology", response.AdminContact.Name);
            Assert.AreEqual("(303) 449-4430", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("netadmin@educause.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("EDUCAUSE", response.AdminContact.Address[0]);
            Assert.AreEqual("4772 Walnut Street", response.AdminContact.Address[1]);
            Assert.AreEqual("Ste 206", response.AdminContact.Address[2]);
            Assert.AreEqual("Boulder, CO 80301", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Information Technology", response.TechnicalContact.Name);
            Assert.AreEqual("(303) 449-4430", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("netadmin@educause.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("EDUCAUSE", response.TechnicalContact.Address[0]);
            Assert.AreEqual("4772 Walnut Street", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ste 206", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Boulder, CO 80301", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns3.educause.edu", response.NameServers[0]);
            Assert.AreEqual("ns4.educause.edu", response.NameServers[1]);
            Assert.AreEqual("ns5.educause.edu", response.NameServers[2]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contacts_case2()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts_case2.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found02", response.TemplateName);

            Assert.AreEqual("stanford.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 05, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1985, 10, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Stanford University", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("The Board of Trustees of the Leland Stanford Junior University", response.Registrant.Address[0]);
            Assert.AreEqual("241 Panama Street, Pine Hall, Room 115", response.Registrant.Address[1]);
            Assert.AreEqual("Stanford, CA 94305-4122", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Domain Admin", response.AdminContact.Name);
            Assert.AreEqual("(650) 723-4328", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("sunet-admin@stanford.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Stanford University", response.AdminContact.Address[0]);
            Assert.AreEqual("241 Panama Street Pine Hall, Room 115", response.AdminContact.Address[1]);
            Assert.AreEqual("Stanford, CA 94305-4122", response.AdminContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Domain Admin", response.TechnicalContact.Name);
            Assert.AreEqual("(650) 723-4328", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("sunet-admin@stanford.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Stanford University", response.TechnicalContact.Address[0]);
            Assert.AreEqual("241 Panama Street Pine Hall, Room 115", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Stanford, CA 94305-4122", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("argus.stanford.edu", response.NameServers[0]);
            Assert.AreEqual("avallone.stanford.edu", response.NameServers[1]);
            Assert.AreEqual("atalante.stanford.edu", response.NameServers[2]);
            Assert.AreEqual("aerathea.stanford.edu", response.NameServers[3]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contacts_case3()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts_case3.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("uiuc.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 03, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1985, 07, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("University of Illinois at Urbana Champaign", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("CITES 1120 Digital Computer Laboratory", response.Registrant.Address[0]);
            Assert.AreEqual("1304 West Springfield Avenue", response.Registrant.Address[1]);
            Assert.AreEqual("Urbana, IL 61801-2910", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Tracy L. Smith", response.AdminContact.Name);
            Assert.AreEqual("(217) 244-2032", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("edu-admin@listserv.illinois.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("University of Illinois at Urbana-Champaign", response.AdminContact.Address[0]);
            Assert.AreEqual("CITES  2105 Digital Computer Laboratory", response.AdminContact.Address[1]);
            Assert.AreEqual("1304 West Springfield Avenue", response.AdminContact.Address[2]);
            Assert.AreEqual("Urbana, IL 61801-4399", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Charles Kline", response.TechnicalContact.Name);
            Assert.AreEqual("(217) 333-3339", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("edu-tech@listserv.illinois.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("University of Illinois at Urbana Champaign", response.TechnicalContact.Address[0]);
            Assert.AreEqual("CITES 1120 Digital Computer Laboratory", response.TechnicalContact.Address[1]);
            Assert.AreEqual("1304 West Springfield Avenue", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Urbana, IL 61801", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("dns1.illinois.edu", response.NameServers[0]);
            Assert.AreEqual("dns2.illinois.edu", response.NameServers[1]);
            Assert.AreEqual("dns1.iu.edu", response.NameServers[2]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contacts_case4()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts_case4.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found02", response.TemplateName);

            Assert.AreEqual("syr.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 07, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1986, 09, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Syracuse University", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Room 200 Machinery Hall", response.Registrant.Address[0]);
            Assert.AreEqual("Syracuse, NY 13244", response.Registrant.Address[1]);
            Assert.AreEqual("UNITED STATES", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("ITS Business Office", response.AdminContact.Name);
            Assert.AreEqual("(315) 443-6189", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("itsoffice@syr.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Syracuse University", response.AdminContact.Address[0]);
            Assert.AreEqual("Information Technology and Services", response.AdminContact.Address[1]);
            Assert.AreEqual("Center for Science and Technology", response.AdminContact.Address[2]);
            Assert.AreEqual("Syracuse, NY 13244", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Networking", response.TechnicalContact.Name);
            Assert.AreEqual("(315) 443-2677", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("ndd@listserv.syr.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Syracuse University", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Room 200 Machinery Hall", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Syracuse, NY 13244", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("lurch.cns.syr.edu", response.NameServers[0]);
            Assert.AreEqual("icarus.syr.edu", response.NameServers[1]);
            Assert.AreEqual("suec1.syr.edu", response.NameServers[2]);
            Assert.AreEqual("ns1.twtelecom.net", response.NameServers[3]);
            Assert.AreEqual("ns2.twtelecom.net", response.NameServers[4]);

            Assert.AreEqual(28, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_registrant()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contact_registrant.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("nic.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 06, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 12, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("North Idaho College", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1000 W. Garden Avenue", response.Registrant.Address[0]);
            Assert.AreEqual("Coeur d'Alene, ID 83814", response.Registrant.Address[1]);
            Assert.AreEqual("UNITED STATES", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("NetAdmin", response.AdminContact.Name);
            Assert.AreEqual("(208) 769-7860", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("netsys@nic.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("North Idaho College", response.AdminContact.Address[0]);
            Assert.AreEqual("1000 W. Garden Avenue", response.AdminContact.Address[1]);
            Assert.AreEqual("Coeur d Alene, ID 83814", response.AdminContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Dennis L Noordam", response.TechnicalContact.Name);
            Assert.AreEqual("(208) 769-7860", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dlnoordam@nic.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Windows System Administrator", response.TechnicalContact.Address[0]);
            Assert.AreEqual("North Idaho College", response.TechnicalContact.Address[1]);
            Assert.AreEqual("1000 W. Garden Avenue", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Coeur d Alene, ID 83814", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("nicns1.nic.edu", response.NameServers[0]);
            Assert.AreEqual("nicns2.nic.edu", response.NameServers[1]);

            Assert.AreEqual(26, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_registrant_without_address()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contact_registrant_without_address.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("mit.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 06, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1985, 05, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Massachusetts Institute of Technology", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("Cambridge, MA 02139", response.Registrant.Address[0]);
            Assert.AreEqual("UNITED STATES", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.AreEqual("Mark Silis", response.AdminContact.Name);
            Assert.AreEqual("(617) 324-5900", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("mark@mit.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Massachusetts Institute of Technology", response.AdminContact.Address[0]);
            Assert.AreEqual("MIT Room W92-167, 77 Massachusetts Avenue", response.AdminContact.Address[1]);
            Assert.AreEqual("Cambridge, MA 02139-4307", response.AdminContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("MIT Network Operations", response.TechnicalContact.Name);
            Assert.AreEqual("(617) 253-8400", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("network@mit.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Massachusetts Institute of Technology", response.TechnicalContact.Address[0]);
            Assert.AreEqual("MIT Room W92-167, 77 Massachusetts Avenue", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Cambridge, MA 02139-4307", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[3]);


            Assert.AreEqual(22, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_registrant_without_zip()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contact_registrant_without_zip.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("aucmed.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 08, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1997, 07, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("The American University of the Caribbean School of Medicine", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("c/o Campbell Corporate Services, Ltd.", response.Registrant.Address[0]);
            Assert.AreEqual("Scotiabank Building, P. O. Box 268", response.Registrant.Address[1]);
            Assert.AreEqual("Grand Cayman", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Ron  Spaide", response.AdminContact.Name);
            Assert.AreEqual("(732) 509-4796", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("rspaide@devrymedical.org", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("VP, CIO", response.AdminContact.Address[0]);
            Assert.AreEqual("Devry Medical International, Inc", response.AdminContact.Address[1]);
            Assert.AreEqual("630 US Highway 1", response.AdminContact.Address[2]);
            Assert.AreEqual("North Brunswick, NJ 08902", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Bill Huber", response.TechnicalContact.Name);
            Assert.AreEqual("(732) 509-4796", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("bhuber@devrymedical.org", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Director, Network Operations", response.TechnicalContact.Address[0]);
            Assert.AreEqual("DeVry Medical International, Inc", response.TechnicalContact.Address[1]);
            Assert.AreEqual("630 US Highway 1", response.TechnicalContact.Address[2]);
            Assert.AreEqual("North Brunswick, NJ 08902", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.geodns.net", response.NameServers[0]);
            Assert.AreEqual("ns2.geodns.net", response.NameServers[1]);

            Assert.AreEqual(26, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_registrant_with_additional_organization()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contact_registrant_with_additional_organization.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("harvard.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 03, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1985, 06, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Harvard University", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("HUIT Network Services", response.Registrant.Address[0]);
            Assert.AreEqual("60 Oxford Street", response.Registrant.Address[1]);
            Assert.AreEqual("Cambridge, MA 02138", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Jacques N Laflamme", response.AdminContact.Name);
            Assert.AreEqual("(617) 384-6663", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("jacques_laflamme@harvard.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Director, Network Services", response.AdminContact.Address[0]);
            Assert.AreEqual("Harvard University", response.AdminContact.Address[1]);
            Assert.AreEqual("60 Oxford Street", response.AdminContact.Address[2]);
            Assert.AreEqual("Cambridge, MA 02138", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Network Operations", response.TechnicalContact.Name);
            Assert.AreEqual("(617) 495-7777", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("netmanager@harvard.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Harvard University", response.TechnicalContact.Address[0]);
            Assert.AreEqual("HUIT Network Services", response.TechnicalContact.Address[1]);
            Assert.AreEqual("60 Oxford Street", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Cambridge, MA 02138", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("externaldns-c1.harvard.edu", response.NameServers[0]);
            Assert.AreEqual("externaldns-c2.harvard.edu", response.NameServers[1]);
            Assert.AreEqual("externaldns-c3.br.harvard.edu", response.NameServers[2]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_found_updated_on_unknown()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_updated_on_unknown.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("pcihealth.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2004, 03, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("PCI Health Training Center", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("8101 John Carpenter Freeway", response.Registrant.Address[0]);
            Assert.AreEqual("Dallas, TX 75247-4720", response.Registrant.Address[1]);
            Assert.AreEqual("UNITED STATES", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Kelly Drake", response.AdminContact.Name);
            Assert.AreEqual("(214) 630-0568", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("kdrake@pcihealth.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("admissions", response.AdminContact.Address[0]);
            Assert.AreEqual("PCI Health Training Center", response.AdminContact.Address[1]);
            Assert.AreEqual("8101 John Carpenter Freeway", response.AdminContact.Address[2]);
            Assert.AreEqual("Dallas, TX 75247-4720", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("daniel Roy", response.TechnicalContact.Name);
            Assert.AreEqual("(214) 215-1764", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dan@nativetechnology.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("InfoTech Services", response.TechnicalContact.Address[0]);
            Assert.AreEqual("PCI Health Training Center", response.TechnicalContact.Address[1]);
            Assert.AreEqual("8101 John Carpenter Freeway", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Dallas, TX 75247-4720", response.TechnicalContact.Address[3]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.maximumasp.com", response.NameServers[0]);
            Assert.AreEqual("ns2.maximumasp.com", response.NameServers[1]);

            Assert.AreEqual(25, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "not_found.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_status_registered.txt");
            var response = parser.Parse("whois.educause.edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.educause.edu/edu/Found01", response.TemplateName);

            Assert.AreEqual("academia.edu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 04, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 05, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Academia", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("251 Kearny St", response.Registrant.Address[0]);
            Assert.AreEqual("suite 520", response.Registrant.Address[1]);
            Assert.AreEqual("San Francisco, CA 94108", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Academia, Inc.", response.AdminContact.Name);
            Assert.AreEqual("(415) 829-2341", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("helpdesk@academia.edu", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("251 Kearny St", response.AdminContact.Address[0]);
            Assert.AreEqual("suite 520", response.AdminContact.Address[1]);
            Assert.AreEqual("San Francisco, CA 94108", response.AdminContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Academia, Inc.", response.TechnicalContact.Name);
            Assert.AreEqual("(415) 829-2341", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("helpdesk@academia.edu", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("251 Kearny St", response.TechnicalContact.Address[0]);
            Assert.AreEqual("suite 520", response.TechnicalContact.Address[1]);
            Assert.AreEqual("San Francisco, CA 94108", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UNITED STATES", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns-1484.awsdns-57.org", response.NameServers[0]);
            Assert.AreEqual("ns-225.awsdns-28.com", response.NameServers[1]);
            Assert.AreEqual("ns-1850.awsdns-39.co.uk", response.NameServers[2]);
            Assert.AreEqual("ns-629.awsdns-14.net", response.NameServers[3]);

            Assert.AreEqual(27, response.FieldsParsed);
        }
    }
}
