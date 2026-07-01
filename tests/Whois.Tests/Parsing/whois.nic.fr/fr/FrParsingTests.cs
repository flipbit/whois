using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fr.Fr
{
    [TestFixture]
    public class FrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("shingara.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("1&1 Internet AG", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 07, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 09, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("ANO00-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Ano Nymous", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("ANO00-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Ano Nymous", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.AreEqual("HU3-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Hostmaster UNETUN", response.TechnicalContact.Name);
            Assert.AreEqual("hostmaster@1and1.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1&1 Internet Sarl.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("7, place de la Gare", response.TechnicalContact.Address[1]);
            Assert.AreEqual("57200 Sarreguemines", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns0.vodkanoire.net", response.NameServers[0]);
            Assert.AreEqual("ns1.vodkanoire.net", response.NameServers[1]);
            Assert.AreEqual("ns2.vodkanoire.net", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(28, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_without_changed()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_contact_without_changed.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("1c2.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MAGIC ON LINE", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2004, 07, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 05, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("U351-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("1C2", response.Registrant.Name);
            Assert.AreEqual("+33 1 30 62 40 06", response.Registrant.TelephoneNumber);
            Assert.AreEqual("jmr@1c2.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("20-22, rue Louis Armand", response.Registrant.Address[0]);
            Assert.AreEqual("75015 Paris", response.Registrant.Address[1]);
            Assert.AreEqual("FR", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("JMR39-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Jean Marc Raimondo", response.AdminContact.Name);
            Assert.AreEqual("+33 1 30 62 40 06", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("jmr@1c2.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1C2", response.AdminContact.Address[0]);
            Assert.AreEqual("20-22, rue Louis Armand", response.AdminContact.Address[1]);
            Assert.AreEqual("75015 Paris", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("HMO7-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Hostmaster Magic OnLine", response.TechnicalContact.Name);
            Assert.AreEqual("+33 1 41 58 22 50", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@magic.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("CTS Informatique", response.TechnicalContact.Address[0]);
            Assert.AreEqual("130-134, avenue du President Wilson", response.TechnicalContact.Address[1]);
            Assert.AreEqual("93512 Montreuil Cedex", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns.magic.fr", response.NameServers[0]);
            Assert.AreEqual("ns2.magic.fr", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(48, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_nameservers.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("google.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("eMARKMONITOR Inc. dba MARKMONITOR", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 06, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 07, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("GI658-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("+1 650 253 0000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600, Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("94043 Mountain View Ca", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("TT599-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Tu Tsao", response.AdminContact.Name);
            Assert.AreEqual("+33 6 50 33 00 10", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Google France", response.AdminContact.Address[0]);
            Assert.AreEqual("38, avenue de l'Opera", response.AdminContact.Address[1]);
            Assert.AreEqual("75002 Paris", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("MC239-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("MARKMONITOR CCOPS", response.TechnicalContact.Name);
            Assert.AreEqual("+01 2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("eMarkmonitor Inc. dba MarkMonitor", response.TechnicalContact.Address[0]);
            Assert.AreEqual("PMB 155", response.TechnicalContact.Address[1]);
            Assert.AreEqual("10400 Overland Road", response.TechnicalContact.Address[2]);
            Assert.AreEqual("83709-1433 Boise, Id", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(44, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_multiple_ipv4()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_nameservers_multiple_ipv4.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("boursedirect.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("FRANCE TELECOM", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2007, 06, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1997, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("BD1013-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("BOURSE DIRECT", response.Registrant.Name);
            Assert.AreEqual("+33 1 56 43 71 85", response.Registrant.TelephoneNumber);
            Assert.AreEqual("hlestrat@boursedirect.fr", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("253, boulevard Pereire", response.Registrant.Address[0]);
            Assert.AreEqual("75852 Paris Cedex 17", response.Registrant.Address[1]);
            Assert.AreEqual("FR", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("HL505-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Herve Lestrat", response.AdminContact.Name);
            Assert.AreEqual("+33 1 56 43 71 85", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("hlestrat@boursedirect.fr", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("BOURSE DIRECT", response.AdminContact.Address[0]);
            Assert.AreEqual("253, boulevard Pereire", response.AdminContact.Address[1]);
            Assert.AreEqual("75852 Paris Cedex 17", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("OH251-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("OLEANE Hostmaster", response.TechnicalContact.Name);
            Assert.AreEqual("+33 1 53 95 14 00", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("domaine-admin@list.orange-ftgroup.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("France Telecom", response.TechnicalContact.Address[0]);
            Assert.AreEqual("13, rue de Javel", response.TechnicalContact.Address[1]);
            Assert.AreEqual("75015 Paris", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.boursedirect.fr", response.NameServers[0]);
            Assert.AreEqual("ns2.boursedirect.fr", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(47, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_with_ipv4_and_some_ipv6()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_nameservers_with_ipv4_and_some_ipv6.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("nic.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("AFNIC registry", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1995, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("AFNI21-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("ASS FRANC NOMMAGE INTERNET EN COOP", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("immeuble international", response.Registrant.Address[0]);
            Assert.AreEqual("2, rue Stephenson", response.Registrant.Address[1]);
            Assert.AreEqual("78181 Montigny-le-Bretonneux", response.Registrant.Address[2]);
            Assert.AreEqual("FR", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("NFC1-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.AdminContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("AFNIC", response.AdminContact.Address[0]);
            Assert.AreEqual("immeuble international", response.AdminContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.AdminContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.AdminContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.AdminContact.Address[4]);
            Assert.AreEqual("FR", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("NFC1-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.TechnicalContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("AFNIC", response.TechnicalContact.Address[0]);
            Assert.AreEqual("immeuble international", response.TechnicalContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.TechnicalContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.TechnicalContact.Address[4]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[5]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.ZoneContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.ZoneContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.AreEqual(6, response.ZoneContact.Address.Count);
            Assert.AreEqual("AFNIC", response.ZoneContact.Address[0]);
            Assert.AreEqual("immeuble international", response.ZoneContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.ZoneContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.ZoneContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.ZoneContact.Address[4]);
            Assert.AreEqual("FR", response.ZoneContact.Address[5]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns1.nic.fr", response.NameServers[0]);
            Assert.AreEqual("ns2.nic.fr", response.NameServers[1]);
            Assert.AreEqual("ns3.nic.fr", response.NameServers[2]);
            Assert.AreEqual("ns1.ext.nic.fr", response.NameServers[3]);
            Assert.AreEqual("ns4.ext.nic.fr", response.NameServers[4]);
            Assert.AreEqual("ns5.ext.nic.fr", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(32, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_active()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_status_active.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("google.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("eMARKMONITOR Inc. dba MARKMONITOR", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 06, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 07, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("GI658-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("+1 650 253 0000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600, Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("94043 Mountain View Ca", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("TT599-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Tu Tsao", response.AdminContact.Name);
            Assert.AreEqual("+33 6 50 33 00 10", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Google France", response.AdminContact.Address[0]);
            Assert.AreEqual("38, avenue de l'Opera", response.AdminContact.Address[1]);
            Assert.AreEqual("75002 Paris", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("MC239-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("MARKMONITOR CCOPS", response.TechnicalContact.Name);
            Assert.AreEqual("+01 2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("eMarkmonitor Inc. dba MarkMonitor", response.TechnicalContact.Address[0]);
            Assert.AreEqual("PMB 155", response.TechnicalContact.Address[1]);
            Assert.AreEqual("10400 Overland Road", response.TechnicalContact.Address[2]);
            Assert.AreEqual("83709-1433 Boise, Id", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(44, response.FieldsParsed);
        }

        [Test]
        public void Test_blocked()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "blocked.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Blocked, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("amazingsales.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("OVH", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 03, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 02, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("A19281-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("UAB AMAZINGSALES.COM", response.Registrant.Name);
            Assert.AreEqual("+370 61282044", response.Registrant.TelephoneNumber);
            Assert.AreEqual("robertas@amazingsales.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Linkmenu g. 15", response.Registrant.Address[0]);
            Assert.AreEqual("LT09300 Vilnius", response.Registrant.Address[1]);
            Assert.AreEqual("LT", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("OVH5-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("OVH NET", response.AdminContact.Name);
            Assert.AreEqual("+33 8 99 70 17 61", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("tech@ovh.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("OVH", response.AdminContact.Address[0]);
            Assert.AreEqual("140, quai du Sartel", response.AdminContact.Address[1]);
            Assert.AreEqual("59100 Roubaix", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("OVH5-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("OVH NET", response.TechnicalContact.Name);
            Assert.AreEqual("+33 8 99 70 17 61", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("tech@ovh.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("OVH", response.TechnicalContact.Address[0]);
            Assert.AreEqual("140, quai du Sartel", response.TechnicalContact.Address[1]);
            Assert.AreEqual("59100 Roubaix", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.interdata.lt", response.NameServers[0]);
            Assert.AreEqual("ns2.interdata.lt", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("BLOCKED", response.DomainStatus[0]);

            Assert.AreEqual(33, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not_found.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound06", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_not_open()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "other_status_not_open.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("asso.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("AFNIC registry", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2007, 06, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1995, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("SFAI2-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Subdomain for associations in France", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("AFNIC", response.Registrant.Address[0]);
            Assert.AreEqual("immeuble international", response.Registrant.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.Registrant.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.Registrant.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.Registrant.Address[4]);
            Assert.AreEqual("FR", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.AreEqual("NFC1-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.AdminContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("AFNIC", response.AdminContact.Address[0]);
            Assert.AreEqual("immeuble international", response.AdminContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.AdminContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.AdminContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.AdminContact.Address[4]);
            Assert.AreEqual("FR", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("NFC1-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.TechnicalContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("AFNIC", response.TechnicalContact.Address[0]);
            Assert.AreEqual("immeuble international", response.TechnicalContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.TechnicalContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.TechnicalContact.Address[4]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[5]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.ZoneContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.ZoneContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.AreEqual(6, response.ZoneContact.Address.Count);
            Assert.AreEqual("AFNIC", response.ZoneContact.Address[0]);
            Assert.AreEqual("immeuble international", response.ZoneContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.ZoneContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.ZoneContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.ZoneContact.Address[4]);
            Assert.AreEqual("FR", response.ZoneContact.Address[5]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("NOT_OPEN", response.DomainStatus[0]);

            Assert.AreEqual(28, response.FieldsParsed);
        }

        [Test]
        public void Test_redemption()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "redemption.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Redemption, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("behotel.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("OVH", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 02, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 01, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("AS1245-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("AUTREMENT SAS", response.Registrant.Name);
            Assert.AreEqual("+33 9 64 18 77 98", response.Registrant.TelephoneNumber);
            Assert.AreEqual("nic-admin@autrementlemail.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("AUTREMENT SAS", response.Registrant.Address[0]);
            Assert.AreEqual("27, rue Fongate", response.Registrant.Address[1]);
            Assert.AreEqual("13006 Marseille", response.Registrant.Address[2]);
            Assert.AreEqual("FR", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("AS1245-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("AUTREMENT SAS", response.AdminContact.Name);
            Assert.AreEqual("+33 9 64 18 77 98", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("nic-admin@autrementlemail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("AUTREMENT SAS", response.AdminContact.Address[0]);
            Assert.AreEqual("27, rue Fongate", response.AdminContact.Address[1]);
            Assert.AreEqual("13006 Marseille", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("OVH5-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("OVH NET", response.TechnicalContact.Name);
            Assert.AreEqual("+33 8 99 70 17 61", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("tech@ovh.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("OVH", response.TechnicalContact.Address[0]);
            Assert.AreEqual("140, quai du Sartel", response.TechnicalContact.Address[1]);
            Assert.AreEqual("59100 Roubaix", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("REDEMPTION", response.DomainStatus[0]);

            Assert.AreEqual(32, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not_found_status_registered.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("behotel.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("OVH", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 01, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 01, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("AS1245-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("AUTREMENT SAS", response.Registrant.Name);
            Assert.AreEqual("+33 9 64 18 77 98", response.Registrant.TelephoneNumber);
            Assert.AreEqual("nic-admin@autrementlemail.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("AUTREMENT SAS", response.Registrant.Address[0]);
            Assert.AreEqual("27, rue Fongate", response.Registrant.Address[1]);
            Assert.AreEqual("13006 Marseille", response.Registrant.Address[2]);
            Assert.AreEqual("FR", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("AS1245-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("AUTREMENT SAS", response.AdminContact.Name);
            Assert.AreEqual("+33 9 64 18 77 98", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("nic-admin@autrementlemail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("AUTREMENT SAS", response.AdminContact.Address[0]);
            Assert.AreEqual("27, rue Fongate", response.AdminContact.Address[1]);
            Assert.AreEqual("13006 Marseille", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("OVH5-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("OVH NET", response.TechnicalContact.Name);
            Assert.AreEqual("+33 8 99 70 17 61", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("tech@ovh.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("OVH", response.TechnicalContact.Address[0]);
            Assert.AreEqual("140, quai du Sartel", response.TechnicalContact.Address[1]);
            Assert.AreEqual("59100 Roubaix", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED", response.DomainStatus[0]);

            Assert.AreEqual(32, response.FieldsParsed);
        }

        [Test]
        public void Test_found_response_contains_contact_remarks()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_response_contains_contact_remarks.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("shingara.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("1&1 Internet AG", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 07, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 09, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("ANO00-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Ano Nymous", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("ANO00-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Ano Nymous", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.AreEqual("HU3-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Hostmaster UNETUN", response.TechnicalContact.Name);
            Assert.AreEqual("hostmaster@1and1.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1&1 Internet Sarl.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("7, place de la Gare", response.TechnicalContact.Address[1]);
            Assert.AreEqual("57200 Sarreguemines", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns0.vodkanoire.net", response.NameServers[0]);
            Assert.AreEqual("ns1.vodkanoire.net", response.NameServers[1]);
            Assert.AreEqual("ns2.vodkanoire.net", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(28, response.FieldsParsed);
        }

        [Test]
        public void Test_found_response_contains_contact_trouble()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_response_contains_contact_trouble.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("hotel.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("GANDI", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2007, 12, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 04, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("ST2122-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("STAR 3", response.Registrant.Name);
            Assert.AreEqual("+33 1 44 51 11 12", response.Registrant.TelephoneNumber);
            Assert.AreEqual("48c80964ab9bf9f034d9e24c306e5035-s3461@contact.gandi.net", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("34, rue Bergere", response.Registrant.Address[0]);
            Assert.AreEqual("75009 Paris", response.Registrant.Address[1]);
            Assert.AreEqual("FR", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("GC2611-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Georges Cachan", response.AdminContact.Name);
            Assert.AreEqual("+33 1 44 51 11 12", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("e13bc247e148d6586dcf316abe00764d-115877@contact.gandi.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("ASTOTEL", response.AdminContact.Address[0]);
            Assert.AreEqual("29, rue de Caumartin", response.AdminContact.Address[1]);
            Assert.AreEqual("75009 Paris", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("GR283-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("GANDI ROLE", response.TechnicalContact.Name);
            Assert.AreEqual("noc@gandi.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Gandi", response.TechnicalContact.Address[0]);
            Assert.AreEqual("15, place de la Nation", response.TechnicalContact.Address[1]);
            Assert.AreEqual("75011 Paris", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("a.dns.gandi.net", response.NameServers[0]);
            Assert.AreEqual("b.dns.gandi.net", response.NameServers[1]);
            Assert.AreEqual("c.dns.gandi.net", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(40, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "throttled.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Throttled02", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound06", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("google.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MARKMONITOR Inc.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2016, 12, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 07, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 12, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GIH6-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Google Ireland Holdings", response.Registrant.Name);
            Assert.AreEqual("+353 14361000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("70 Sir John Rogersons Quay", response.Registrant.Address[0]);
            Assert.AreEqual("2 Dublin", response.Registrant.Address[1]);
            Assert.AreEqual("IE", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("GIH5-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Google Ireland Holdings", response.AdminContact.Name);
            Assert.AreEqual("+353 14361000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("70 Sir John Rogersons Quay", response.AdminContact.Address[0]);
            Assert.AreEqual("2 Dublin", response.AdminContact.Address[1]);
            Assert.AreEqual("IE", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("CP4370-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Ccops Provisioning", response.TechnicalContact.Name);
            Assert.AreEqual("+1 2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("MarkMonitor", response.TechnicalContact.Address[0]);
            Assert.AreEqual("10400 Overland Rd.", response.TechnicalContact.Address[1]);
            Assert.AreEqual("PMB 155", response.TechnicalContact.Address[2]);
            Assert.AreEqual("83709 Boise", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(43, response.FieldsParsed);
        }
    }
}
