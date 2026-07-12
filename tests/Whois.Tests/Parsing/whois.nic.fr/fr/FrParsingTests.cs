using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fr.Fr
{
    public class FrParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public FrParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("shingara.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("1&1 Internet AG", response.Registrar.Name);

            Assert.Equal(new DateTime(2009, 07, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2007, 09, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("ANO00-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("Ano Nymous", response.Registrant.Name);


             // AdminContact Details
            Assert.Equal("ANO00-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("Ano Nymous", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.Equal("HU3-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Hostmaster UNETUN", response.TechnicalContact.Name);
            Assert.Equal("hostmaster@1and1.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1&1 Internet Sarl.", response.TechnicalContact.Address[0]);
            Assert.Equal("7, place de la Gare", response.TechnicalContact.Address[1]);
            Assert.Equal("57200 Sarreguemines", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns0.vodkanoire.net", response.NameServers[0]);
            Assert.Equal("ns1.vodkanoire.net", response.NameServers[1]);
            Assert.Equal("ns2.vodkanoire.net", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(28, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_contact_without_changed()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found_contact_without_changed.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("1c2.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MAGIC ON LINE", response.Registrar.Name);

            Assert.Equal(new DateTime(2004, 07, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 05, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("U351-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("1C2", response.Registrant.Name);
            Assert.Equal("+33 1 30 62 40 06", response.Registrant.TelephoneNumber);
            Assert.Equal("jmr@1c2.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("20-22, rue Louis Armand", response.Registrant.Address[0]);
            Assert.Equal("75015 Paris", response.Registrant.Address[1]);
            Assert.Equal("FR", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("JMR39-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("Jean Marc Raimondo", response.AdminContact.Name);
            Assert.Equal("+33 1 30 62 40 06", response.AdminContact.TelephoneNumber);
            Assert.Equal("jmr@1c2.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("1C2", response.AdminContact.Address[0]);
            Assert.Equal("20-22, rue Louis Armand", response.AdminContact.Address[1]);
            Assert.Equal("75015 Paris", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("HMO7-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Hostmaster Magic OnLine", response.TechnicalContact.Name);
            Assert.Equal("+33 1 41 58 22 50", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("hostmaster@magic.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("CTS Informatique", response.TechnicalContact.Address[0]);
            Assert.Equal("130-134, avenue du President Wilson", response.TechnicalContact.Address[1]);
            Assert.Equal("93512 Montreuil Cedex", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns.magic.fr", response.NameServers[0]);
            Assert.Equal("ns2.magic.fr", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(48, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_nameservers()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found_nameservers.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("google.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("eMARKMONITOR Inc. dba MARKMONITOR", response.Registrar.Name);

            Assert.Equal(new DateTime(2009, 06, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2000, 07, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("GI658-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("+1 650 253 0000", response.Registrant.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600, Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("94043 Mountain View Ca", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("TT599-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("Tu Tsao", response.AdminContact.Name);
            Assert.Equal("+33 6 50 33 00 10", response.AdminContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Google France", response.AdminContact.Address[0]);
            Assert.Equal("38, avenue de l'Opera", response.AdminContact.Address[1]);
            Assert.Equal("75002 Paris", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("MC239-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("MARKMONITOR CCOPS", response.TechnicalContact.Name);
            Assert.Equal("+01 2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("eMarkmonitor Inc. dba MarkMonitor", response.TechnicalContact.Address[0]);
            Assert.Equal("PMB 155", response.TechnicalContact.Address[1]);
            Assert.Equal("10400 Overland Road", response.TechnicalContact.Address[2]);
            Assert.Equal("83709-1433 Boise, Id", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(44, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_nameservers_multiple_ipv4()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found_nameservers_multiple_ipv4.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("boursedirect.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("FRANCE TELECOM", response.Registrar.Name);

            Assert.Equal(new DateTime(2007, 06, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1997, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("BD1013-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("BOURSE DIRECT", response.Registrant.Name);
            Assert.Equal("+33 1 56 43 71 85", response.Registrant.TelephoneNumber);
            Assert.Equal("hlestrat@boursedirect.fr", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("253, boulevard Pereire", response.Registrant.Address[0]);
            Assert.Equal("75852 Paris Cedex 17", response.Registrant.Address[1]);
            Assert.Equal("FR", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("HL505-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("Herve Lestrat", response.AdminContact.Name);
            Assert.Equal("+33 1 56 43 71 85", response.AdminContact.TelephoneNumber);
            Assert.Equal("hlestrat@boursedirect.fr", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("BOURSE DIRECT", response.AdminContact.Address[0]);
            Assert.Equal("253, boulevard Pereire", response.AdminContact.Address[1]);
            Assert.Equal("75852 Paris Cedex 17", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("OH251-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("OLEANE Hostmaster", response.TechnicalContact.Name);
            Assert.Equal("+33 1 53 95 14 00", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("domaine-admin@list.orange-ftgroup.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("France Telecom", response.TechnicalContact.Address[0]);
            Assert.Equal("13, rue de Javel", response.TechnicalContact.Address[1]);
            Assert.Equal("75015 Paris", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.boursedirect.fr", response.NameServers[0]);
            Assert.Equal("ns2.boursedirect.fr", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(47, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_nameservers_with_ipv4_and_some_ipv6()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found_nameservers_with_ipv4_and_some_ipv6.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("nic.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("AFNIC registry", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1995, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("AFNI21-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("ASS FRANC NOMMAGE INTERNET EN COOP", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("immeuble international", response.Registrant.Address[0]);
            Assert.Equal("2, rue Stephenson", response.Registrant.Address[1]);
            Assert.Equal("78181 Montigny-le-Bretonneux", response.Registrant.Address[2]);
            Assert.Equal("FR", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("NFC1-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("NIC France Contact", response.AdminContact.Name);
            Assert.Equal("+33 1 39 30 83 00", response.AdminContact.TelephoneNumber);
            Assert.Equal("hostmaster@nic.fr", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("AFNIC", response.AdminContact.Address[0]);
            Assert.Equal("immeuble international", response.AdminContact.Address[1]);
            Assert.Equal("2, rue Stephenson", response.AdminContact.Address[2]);
            Assert.Equal("Montigny le Bretonneux", response.AdminContact.Address[3]);
            Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.AdminContact.Address[4]);
            Assert.Equal("FR", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("NFC1-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("NIC France Contact", response.TechnicalContact.Name);
            Assert.Equal("+33 1 39 30 83 00", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("hostmaster@nic.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("AFNIC", response.TechnicalContact.Address[0]);
            Assert.Equal("immeuble international", response.TechnicalContact.Address[1]);
            Assert.Equal("2, rue Stephenson", response.TechnicalContact.Address[2]);
            Assert.Equal("Montigny le Bretonneux", response.TechnicalContact.Address[3]);
            Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.TechnicalContact.Address[4]);
            Assert.Equal("FR", response.TechnicalContact.Address[5]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);
            Assert.Equal("NIC France Contact", response.ZoneContact.Name);
            Assert.Equal("+33 1 39 30 83 00", response.ZoneContact.TelephoneNumber);
            Assert.Equal("hostmaster@nic.fr", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.Equal(6, response.ZoneContact.Address.Count);
            Assert.Equal("AFNIC", response.ZoneContact.Address[0]);
            Assert.Equal("immeuble international", response.ZoneContact.Address[1]);
            Assert.Equal("2, rue Stephenson", response.ZoneContact.Address[2]);
            Assert.Equal("Montigny le Bretonneux", response.ZoneContact.Address[3]);
            Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.ZoneContact.Address[4]);
            Assert.Equal("FR", response.ZoneContact.Address[5]);


            // Nameservers
            Assert.Equal(6, response.NameServers.Count);
            Assert.Equal("ns1.nic.fr", response.NameServers[0]);
            Assert.Equal("ns2.nic.fr", response.NameServers[1]);
            Assert.Equal("ns3.nic.fr", response.NameServers[2]);
            Assert.Equal("ns1.ext.nic.fr", response.NameServers[3]);
            Assert.Equal("ns4.ext.nic.fr", response.NameServers[4]);
            Assert.Equal("ns5.ext.nic.fr", response.NameServers[5]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(32, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_active()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found_status_active.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("google.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("eMARKMONITOR Inc. dba MARKMONITOR", response.Registrar.Name);

            Assert.Equal(new DateTime(2009, 06, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2000, 07, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("GI658-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("+1 650 253 0000", response.Registrant.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600, Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("94043 Mountain View Ca", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("TT599-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("Tu Tsao", response.AdminContact.Name);
            Assert.Equal("+33 6 50 33 00 10", response.AdminContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Google France", response.AdminContact.Address[0]);
            Assert.Equal("38, avenue de l'Opera", response.AdminContact.Address[1]);
            Assert.Equal("75002 Paris", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("MC239-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("MARKMONITOR CCOPS", response.TechnicalContact.Name);
            Assert.Equal("+01 2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("eMarkmonitor Inc. dba MarkMonitor", response.TechnicalContact.Address[0]);
            Assert.Equal("PMB 155", response.TechnicalContact.Address[1]);
            Assert.Equal("10400 Overland Road", response.TechnicalContact.Address[2]);
            Assert.Equal("83709-1433 Boise, Id", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(44, response.FieldsParsed);
        }

        [Fact]
        public void Test_blocked()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "blocked", "blocked.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Blocked, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("amazingsales.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("OVH", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 03, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 02, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("A19281-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("UAB AMAZINGSALES.COM", response.Registrant.Name);
            Assert.Equal("+370 61282044", response.Registrant.TelephoneNumber);
            Assert.Equal("robertas@amazingsales.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Linkmenu g. 15", response.Registrant.Address[0]);
            Assert.Equal("LT09300 Vilnius", response.Registrant.Address[1]);
            Assert.Equal("LT", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("OVH5-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("OVH NET", response.AdminContact.Name);
            Assert.Equal("+33 8 99 70 17 61", response.AdminContact.TelephoneNumber);
            Assert.Equal("tech@ovh.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("OVH", response.AdminContact.Address[0]);
            Assert.Equal("140, quai du Sartel", response.AdminContact.Address[1]);
            Assert.Equal("59100 Roubaix", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("OVH5-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("OVH NET", response.TechnicalContact.Name);
            Assert.Equal("+33 8 99 70 17 61", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("tech@ovh.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("OVH", response.TechnicalContact.Address[0]);
            Assert.Equal("140, quai du Sartel", response.TechnicalContact.Address[1]);
            Assert.Equal("59100 Roubaix", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.interdata.lt", response.NameServers[0]);
            Assert.Equal("ns2.interdata.lt", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("BLOCKED", response.DomainStatus[0]);

            Assert.Equal(33, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/06", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_not_open()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "other_status_not_open.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("asso.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("AFNIC registry", response.Registrar.Name);

            Assert.Equal(new DateTime(2007, 06, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1995, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("SFAI2-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("Subdomain for associations in France", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("AFNIC", response.Registrant.Address[0]);
            Assert.Equal("immeuble international", response.Registrant.Address[1]);
            Assert.Equal("2, rue Stephenson", response.Registrant.Address[2]);
            Assert.Equal("Montigny le Bretonneux", response.Registrant.Address[3]);
            Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.Registrant.Address[4]);
            Assert.Equal("FR", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.Equal("NFC1-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("NIC France Contact", response.AdminContact.Name);
            Assert.Equal("+33 1 39 30 83 00", response.AdminContact.TelephoneNumber);
            Assert.Equal("hostmaster@nic.fr", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("AFNIC", response.AdminContact.Address[0]);
            Assert.Equal("immeuble international", response.AdminContact.Address[1]);
            Assert.Equal("2, rue Stephenson", response.AdminContact.Address[2]);
            Assert.Equal("Montigny le Bretonneux", response.AdminContact.Address[3]);
            Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.AdminContact.Address[4]);
            Assert.Equal("FR", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("NFC1-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("NIC France Contact", response.TechnicalContact.Name);
            Assert.Equal("+33 1 39 30 83 00", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("hostmaster@nic.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("AFNIC", response.TechnicalContact.Address[0]);
            Assert.Equal("immeuble international", response.TechnicalContact.Address[1]);
            Assert.Equal("2, rue Stephenson", response.TechnicalContact.Address[2]);
            Assert.Equal("Montigny le Bretonneux", response.TechnicalContact.Address[3]);
            Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.TechnicalContact.Address[4]);
            Assert.Equal("FR", response.TechnicalContact.Address[5]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);
            Assert.Equal("NIC France Contact", response.ZoneContact.Name);
            Assert.Equal("+33 1 39 30 83 00", response.ZoneContact.TelephoneNumber);
            Assert.Equal("hostmaster@nic.fr", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.Equal(6, response.ZoneContact.Address.Count);
            Assert.Equal("AFNIC", response.ZoneContact.Address[0]);
            Assert.Equal("immeuble international", response.ZoneContact.Address[1]);
            Assert.Equal("2, rue Stephenson", response.ZoneContact.Address[2]);
            Assert.Equal("Montigny le Bretonneux", response.ZoneContact.Address[3]);
            Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.ZoneContact.Address[4]);
            Assert.Equal("FR", response.ZoneContact.Address[5]);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("NOT_OPEN", response.DomainStatus[0]);

            Assert.Equal(28, response.FieldsParsed);
        }

        [Fact]
        public void Test_redemption()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "redemption", "redemption.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Redemption, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("behotel.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("OVH", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 02, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 01, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("AS1245-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("AUTREMENT SAS", response.Registrant.Name);
            Assert.Equal("+33 9 64 18 77 98", response.Registrant.TelephoneNumber);
            Assert.Equal("nic-admin@autrementlemail.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("AUTREMENT SAS", response.Registrant.Address[0]);
            Assert.Equal("27, rue Fongate", response.Registrant.Address[1]);
            Assert.Equal("13006 Marseille", response.Registrant.Address[2]);
            Assert.Equal("FR", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("AS1245-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("AUTREMENT SAS", response.AdminContact.Name);
            Assert.Equal("+33 9 64 18 77 98", response.AdminContact.TelephoneNumber);
            Assert.Equal("nic-admin@autrementlemail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("AUTREMENT SAS", response.AdminContact.Address[0]);
            Assert.Equal("27, rue Fongate", response.AdminContact.Address[1]);
            Assert.Equal("13006 Marseille", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("OVH5-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("OVH NET", response.TechnicalContact.Name);
            Assert.Equal("+33 8 99 70 17 61", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("tech@ovh.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("OVH", response.TechnicalContact.Address[0]);
            Assert.Equal("140, quai du Sartel", response.TechnicalContact.Address[1]);
            Assert.Equal("59100 Roubaix", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("REDEMPTION", response.DomainStatus[0]);

            Assert.Equal(32, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not-found", "not_found_status_registered.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("behotel.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("OVH", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 01, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 01, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("AS1245-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("AUTREMENT SAS", response.Registrant.Name);
            Assert.Equal("+33 9 64 18 77 98", response.Registrant.TelephoneNumber);
            Assert.Equal("nic-admin@autrementlemail.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("AUTREMENT SAS", response.Registrant.Address[0]);
            Assert.Equal("27, rue Fongate", response.Registrant.Address[1]);
            Assert.Equal("13006 Marseille", response.Registrant.Address[2]);
            Assert.Equal("FR", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("AS1245-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("AUTREMENT SAS", response.AdminContact.Name);
            Assert.Equal("+33 9 64 18 77 98", response.AdminContact.TelephoneNumber);
            Assert.Equal("nic-admin@autrementlemail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("AUTREMENT SAS", response.AdminContact.Address[0]);
            Assert.Equal("27, rue Fongate", response.AdminContact.Address[1]);
            Assert.Equal("13006 Marseille", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("OVH5-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("OVH NET", response.TechnicalContact.Name);
            Assert.Equal("+33 8 99 70 17 61", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("tech@ovh.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("OVH", response.TechnicalContact.Address[0]);
            Assert.Equal("140, quai du Sartel", response.TechnicalContact.Address[1]);
            Assert.Equal("59100 Roubaix", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("REGISTERED", response.DomainStatus[0]);

            Assert.Equal(32, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_response_contains_contact_remarks()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found_response_contains_contact_remarks.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("shingara.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("1&1 Internet AG", response.Registrar.Name);

            Assert.Equal(new DateTime(2009, 07, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2007, 09, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("ANO00-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("Ano Nymous", response.Registrant.Name);


             // AdminContact Details
            Assert.Equal("ANO00-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("Ano Nymous", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.Equal("HU3-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Hostmaster UNETUN", response.TechnicalContact.Name);
            Assert.Equal("hostmaster@1and1.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1&1 Internet Sarl.", response.TechnicalContact.Address[0]);
            Assert.Equal("7, place de la Gare", response.TechnicalContact.Address[1]);
            Assert.Equal("57200 Sarreguemines", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns0.vodkanoire.net", response.NameServers[0]);
            Assert.Equal("ns1.vodkanoire.net", response.NameServers[1]);
            Assert.Equal("ns2.vodkanoire.net", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(28, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_response_contains_contact_trouble()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found_response_contains_contact_trouble.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("hotel.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("GANDI", response.Registrar.Name);

            Assert.Equal(new DateTime(2007, 12, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2000, 04, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("ST2122-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("STAR 3", response.Registrant.Name);
            Assert.Equal("+33 1 44 51 11 12", response.Registrant.TelephoneNumber);
            Assert.Equal("48c80964ab9bf9f034d9e24c306e5035-s3461@contact.gandi.net", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("34, rue Bergere", response.Registrant.Address[0]);
            Assert.Equal("75009 Paris", response.Registrant.Address[1]);
            Assert.Equal("FR", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("GC2611-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("Georges Cachan", response.AdminContact.Name);
            Assert.Equal("+33 1 44 51 11 12", response.AdminContact.TelephoneNumber);
            Assert.Equal("e13bc247e148d6586dcf316abe00764d-115877@contact.gandi.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("ASTOTEL", response.AdminContact.Address[0]);
            Assert.Equal("29, rue de Caumartin", response.AdminContact.Address[1]);
            Assert.Equal("75009 Paris", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("GR283-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("GANDI ROLE", response.TechnicalContact.Name);
            Assert.Equal("noc@gandi.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Gandi", response.TechnicalContact.Address[0]);
            Assert.Equal("15, place de la Nation", response.TechnicalContact.Address[1]);
            Assert.Equal("75011 Paris", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("a.dns.gandi.net", response.NameServers[0]);
            Assert.Equal("b.dns.gandi.net", response.NameServers[1]);
            Assert.Equal("c.dns.gandi.net", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(40, response.FieldsParsed);
        }

        [Fact]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "throttled", "throttled.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Throttled, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/throttled/02", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not-found", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/06", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/05", response.TemplateName);

            Assert.Equal("google.fr", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MARKMONITOR Inc.", response.Registrar.Name);

            Assert.Equal(new DateTime(2016, 12, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2000, 07, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2017, 12, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("GIH6-FRNIC", response.Registrant.RegistryId);
            Assert.Equal("Google Ireland Holdings", response.Registrant.Name);
            Assert.Equal("+353 14361000", response.Registrant.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("70 Sir John Rogersons Quay", response.Registrant.Address[0]);
            Assert.Equal("2 Dublin", response.Registrant.Address[1]);
            Assert.Equal("IE", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("GIH5-FRNIC", response.AdminContact.RegistryId);
            Assert.Equal("Google Ireland Holdings", response.AdminContact.Name);
            Assert.Equal("+353 14361000", response.AdminContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("70 Sir John Rogersons Quay", response.AdminContact.Address[0]);
            Assert.Equal("2 Dublin", response.AdminContact.Address[1]);
            Assert.Equal("IE", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("CP4370-FRNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Ccops Provisioning", response.TechnicalContact.Name);
            Assert.Equal("+1 2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("MarkMonitor", response.TechnicalContact.Address[0]);
            Assert.Equal("10400 Overland Rd.", response.TechnicalContact.Address[1]);
            Assert.Equal("PMB 155", response.TechnicalContact.Address[2]);
            Assert.Equal("83709 Boise", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(43, response.FieldsParsed);
        }
    }
}
