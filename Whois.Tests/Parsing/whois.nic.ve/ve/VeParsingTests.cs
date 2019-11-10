using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ve.Ve
{
    [TestFixture]
    public class VeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("ula.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2005, 11, 17, 21, 16, 31, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 11, 15, 14, 40, 48, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("ula.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.Registrant.Name);
            Assert.AreEqual("+582127718584", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.Registrant.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("ULA", response.Registrant.Address[0]);
            Assert.AreEqual("Merida", response.Registrant.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("ula.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.AdminContact.Name);
            Assert.AreEqual("+582127718584", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.AdminContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("ULA", response.AdminContact.Address[0]);
            Assert.AreEqual("Merida", response.AdminContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("ula.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.BillingContact.Name);
            Assert.AreEqual("+582127718584", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.BillingContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("ULA", response.BillingContact.Address[0]);
            Assert.AreEqual("Merida", response.BillingContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("ula.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.TechnicalContact.Name);
            Assert.AreEqual("+582127718584", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("ULA", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Merida", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("avalon.ula.ve", response.NameServers[0]);
            Assert.AreEqual("azmodan.ula.ve", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVO", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_nameservers.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("ula.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2005, 11, 17, 21, 16, 31, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 11, 15, 14, 40, 48, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("ula.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.Registrant.Name);
            Assert.AreEqual("+582127718584", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.Registrant.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("ULA", response.Registrant.Address[0]);
            Assert.AreEqual("Merida", response.Registrant.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("ula.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.AdminContact.Name);
            Assert.AreEqual("+582127718584", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.AdminContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("ULA", response.AdminContact.Address[0]);
            Assert.AreEqual("Merida", response.AdminContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("ula.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.BillingContact.Name);
            Assert.AreEqual("+582127718584", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.BillingContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("ULA", response.BillingContact.Address[0]);
            Assert.AreEqual("Merida", response.BillingContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("ula.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.TechnicalContact.Name);
            Assert.AreEqual("+582127718584", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("ULA", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Merida", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("avalon.ula.ve", response.NameServers[0]);
            Assert.AreEqual("azmodan.ula.ve", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVO", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_missing()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_nameservers_missing.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("zumba.com.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("zumba.com.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.Registrant.Name);
            Assert.AreEqual("3-97836844", response.Registrant.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.Registrant.Address[0]);
            Assert.AreEqual("GPO Box 988", response.Registrant.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("zumba.com.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.AdminContact.Name);
            Assert.AreEqual("3-97831800", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("3-97836844", response.AdminContact.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.AdminContact.Address[0]);
            Assert.AreEqual("GPO Box 988", response.AdminContact.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("zumba.com.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Juan Enrique Sanchez Serrano", response.BillingContact.Name);
            Assert.AreEqual("2691300", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("3437840", response.BillingContact.FaxNumber);
            Assert.AreEqual("mail@nameaction.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("NameAction Inc", response.BillingContact.Address[0]);
            Assert.AreEqual("Av. Providencia 201, Of. 22", response.BillingContact.Address[1]);
            Assert.AreEqual("Santiago  CL", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("zumba.com.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.TechnicalContact.Name);
            Assert.AreEqual("3-97831800", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("3-97836844", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.TechnicalContact.Address[0]);
            Assert.AreEqual("GPO Box 988", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.TechnicalContact.Address[2]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVO", response.DomainStatus[0]);

            Assert.AreEqual(36, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_activo()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_status_activo.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("zumba.com.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("zumba.com.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.Registrant.Name);
            Assert.AreEqual("3-97836844", response.Registrant.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.Registrant.Address[0]);
            Assert.AreEqual("GPO Box 988", response.Registrant.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("zumba.com.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.AdminContact.Name);
            Assert.AreEqual("3-97831800", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("3-97836844", response.AdminContact.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.AdminContact.Address[0]);
            Assert.AreEqual("GPO Box 988", response.AdminContact.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("zumba.com.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Juan Enrique Sanchez Serrano", response.BillingContact.Name);
            Assert.AreEqual("2691300", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("3437840", response.BillingContact.FaxNumber);
            Assert.AreEqual("mail@nameaction.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("NameAction Inc", response.BillingContact.Address[0]);
            Assert.AreEqual("Av. Providencia 201, Of. 22", response.BillingContact.Address[1]);
            Assert.AreEqual("Santiago  CL", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("zumba.com.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.TechnicalContact.Name);
            Assert.AreEqual("3-97831800", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("3-97836844", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.TechnicalContact.Address[0]);
            Assert.AreEqual("GPO Box 988", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.TechnicalContact.Address[2]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVO", response.DomainStatus[0]);

            Assert.AreEqual(36, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "not_found.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ve", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "suspended.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Suspended, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("aloespa.com.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2006, 06, 08, 21, 54, 41, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 11, 21, 15, 21, 32, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 11, 21, 15, 21, 32, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("aloespa.com.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Rafael Perez", response.Registrant.Name);
            Assert.AreEqual("registro@tepuynet.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Rafael Perez", response.Registrant.Address[0]);
            Assert.AreEqual("Caracas", response.Registrant.Address[1]);
            Assert.AreEqual("Caracas, D. Federal  VE", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("aloespa.com.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Tepuynet", response.AdminContact.Name);
            Assert.AreEqual("2418246437", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("2418246437", response.AdminContact.FaxNumber);
            Assert.AreEqual("registro@tepuynet.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Tepuynet C.A.", response.AdminContact.Address[0]);
            Assert.AreEqual("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.AdminContact.Address[1]);
            Assert.AreEqual("Valencia, Carabobo  VE", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("aloespa.com.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Tepuynet", response.BillingContact.Name);
            Assert.AreEqual("2418246437", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("2418246437", response.BillingContact.FaxNumber);
            Assert.AreEqual("registro@tepuynet.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("Tepuynet C.A.", response.BillingContact.Address[0]);
            Assert.AreEqual("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.BillingContact.Address[1]);
            Assert.AreEqual("Valencia, Carabobo  VE", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("aloespa.com.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Tepuynet", response.TechnicalContact.Name);
            Assert.AreEqual("2418246437", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("2418246437", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("registro@tepuynet.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Tepuynet C.A.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Valencia, Carabobo  VE", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns10.tepuyserver.net", response.NameServers[0]);
            Assert.AreEqual("ns9.tepuyserver.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("SUSPENDIDO", response.DomainStatus[0]);

            Assert.AreEqual(38, response.FieldsParsed);
        }

        [Test]
        public void Test_found_updated_on()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_updated_on.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("ula.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2005, 11, 17, 21, 16, 31, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 11, 15, 14, 40, 48, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("ula.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.Registrant.Name);
            Assert.AreEqual("+582127718584", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.Registrant.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("ULA", response.Registrant.Address[0]);
            Assert.AreEqual("Merida", response.Registrant.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("ula.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.AdminContact.Name);
            Assert.AreEqual("+582127718584", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.AdminContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("ULA", response.AdminContact.Address[0]);
            Assert.AreEqual("Merida", response.AdminContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("ula.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.BillingContact.Name);
            Assert.AreEqual("+582127718584", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.BillingContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("ULA", response.BillingContact.Address[0]);
            Assert.AreEqual("Merida", response.BillingContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("ula.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Universidad de los Andes", response.TechnicalContact.Name);
            Assert.AreEqual("+582127718584", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+582127718599", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("fobispo@nic.ve", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("ULA", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Merida", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Merida, Merida  VE", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("avalon.ula.ve", response.NameServers[0]);
            Assert.AreEqual("azmodan.ula.ve", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVO", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_found_updated_on_blank()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_updated_on_blank.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("zumba.com.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("zumba.com.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.Registrant.Name);
            Assert.AreEqual("3-97836844", response.Registrant.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.Registrant.Address[0]);
            Assert.AreEqual("GPO Box 988", response.Registrant.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("zumba.com.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.AdminContact.Name);
            Assert.AreEqual("3-97831800", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("3-97836844", response.AdminContact.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.AdminContact.Address[0]);
            Assert.AreEqual("GPO Box 988", response.AdminContact.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("zumba.com.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Juan Enrique Sanchez Serrano", response.BillingContact.Name);
            Assert.AreEqual("2691300", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("3437840", response.BillingContact.FaxNumber);
            Assert.AreEqual("mail@nameaction.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("NameAction Inc", response.BillingContact.Address[0]);
            Assert.AreEqual("Av. Providencia 201, Of. 22", response.BillingContact.Address[1]);
            Assert.AreEqual("Santiago  CL", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("zumba.com.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.TechnicalContact.Name);
            Assert.AreEqual("3-97831800", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("3-97836844", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.TechnicalContact.Address[0]);
            Assert.AreEqual("GPO Box 988", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.TechnicalContact.Address[2]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVO", response.DomainStatus[0]);

            Assert.AreEqual(36, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ve", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_inactive()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "inactive.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Suspended, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("aloespa.com.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2006, 06, 08, 21, 54, 41, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 11, 21, 15, 21, 32, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 11, 21, 15, 21, 32, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("aloespa.com.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Rafael Perez", response.Registrant.Name);
            Assert.AreEqual("registro@tepuynet.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Rafael Perez", response.Registrant.Address[0]);
            Assert.AreEqual("Caracas", response.Registrant.Address[1]);
            Assert.AreEqual("Caracas, D. Federal  VE", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("aloespa.com.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Tepuynet", response.AdminContact.Name);
            Assert.AreEqual("2418246437", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("2418246437", response.AdminContact.FaxNumber);
            Assert.AreEqual("registro@tepuynet.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Tepuynet C.A.", response.AdminContact.Address[0]);
            Assert.AreEqual("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.AdminContact.Address[1]);
            Assert.AreEqual("Valencia, Carabobo  VE", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("aloespa.com.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Tepuynet", response.BillingContact.Name);
            Assert.AreEqual("2418246437", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("2418246437", response.BillingContact.FaxNumber);
            Assert.AreEqual("registro@tepuynet.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("Tepuynet C.A.", response.BillingContact.Address[0]);
            Assert.AreEqual("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.BillingContact.Address[1]);
            Assert.AreEqual("Valencia, Carabobo  VE", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("aloespa.com.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Tepuynet", response.TechnicalContact.Name);
            Assert.AreEqual("2418246437", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("2418246437", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("registro@tepuynet.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Tepuynet C.A.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Valencia, Carabobo  VE", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns10.tepuyserver.net", response.NameServers[0]);
            Assert.AreEqual("ns9.tepuyserver.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("SUSPENDIDO", response.DomainStatus[0]);

            Assert.AreEqual(38, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ve/ve/Found", response.TemplateName);

            Assert.AreEqual("zumba.com.ve", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("zumba.com.ve-dom", response.Registrant.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.Registrant.Name);
            Assert.AreEqual("3-97836844", response.Registrant.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.Registrant.Address[0]);
            Assert.AreEqual("GPO Box 988", response.Registrant.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("zumba.com.ve-adm", response.AdminContact.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.AdminContact.Name);
            Assert.AreEqual("3-97831800", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("3-97836844", response.AdminContact.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.AdminContact.Address[0]);
            Assert.AreEqual("GPO Box 988", response.AdminContact.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("zumba.com.ve-bil", response.BillingContact.RegistryId);
            Assert.AreEqual("Juan Enrique Sanchez Serrano", response.BillingContact.Name);
            Assert.AreEqual("2691300", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("3437840", response.BillingContact.FaxNumber);
            Assert.AreEqual("mail@nameaction.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("NameAction Inc", response.BillingContact.Address[0]);
            Assert.AreEqual("Av. Providencia 201, Of. 22", response.BillingContact.Address[1]);
            Assert.AreEqual("Santiago  CL", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("zumba.com.ve-tec", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Instra  Corporation Pty Ltd", response.TechnicalContact.Name);
            Assert.AreEqual("3-97831800", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("3-97836844", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("instracorp@nameaction.com.ve", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Instra Corporation Pty Ltd", response.TechnicalContact.Address[0]);
            Assert.AreEqual("GPO Box 988", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Melbourne  AU", response.TechnicalContact.Address[2]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVO", response.DomainStatus[0]);

            Assert.AreEqual(36, response.FieldsParsed);
        }
    }
}
