using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ve.Ve;

public class VeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public VeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "found", "ula.ve.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/05", response.TemplateName);

        Assert.Null(response.DomainName);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Equal(" CON000011396", response.AdminContact.RegistryId);
        Assert.Null(response.AdminContact.Name);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(0, response.AdminContact.Address.Count);


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Equal(" CON000011396", response.TechnicalContact.RegistryId);
        Assert.Null(response.TechnicalContact.Name);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(0, response.TechnicalContact.Address.Count);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Equal(9, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_nameservers()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "found", "found_nameservers.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ve/ve/found/01", response.TemplateName);

        Assert.Equal("ula.ve", response.DomainName.ToString());

        Assert.Equal(new DateTime(2005, 11, 17, 21, 16, 31, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 11, 15, 14, 40, 48, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("ula.ve-dom", response.Registrant.RegistryId);
        Assert.Equal("Universidad de los Andes", response.Registrant.Name);
        Assert.Equal("+582127718584", response.Registrant.TelephoneNumber);
        Assert.Equal("+582127718599", response.Registrant.FaxNumber);
        Assert.Equal("fobispo@nic.ve", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("ULA", response.Registrant.Address[0]);
        Assert.Equal("Merida", response.Registrant.Address[1]);
        Assert.Equal("Merida, Merida  VE", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("ula.ve-adm", response.AdminContact.RegistryId);
        Assert.Equal("Universidad de los Andes", response.AdminContact.Name);
        Assert.Equal("+582127718584", response.AdminContact.TelephoneNumber);
        Assert.Equal("+582127718599", response.AdminContact.FaxNumber);
        Assert.Equal("fobispo@nic.ve", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("ULA", response.AdminContact.Address[0]);
        Assert.Equal("Merida", response.AdminContact.Address[1]);
        Assert.Equal("Merida, Merida  VE", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("ula.ve-bil", response.BillingContact.RegistryId);
        Assert.Equal("Universidad de los Andes", response.BillingContact.Name);
        Assert.Equal("+582127718584", response.BillingContact.TelephoneNumber);
        Assert.Equal("+582127718599", response.BillingContact.FaxNumber);
        Assert.Equal("fobispo@nic.ve", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("ULA", response.BillingContact.Address[0]);
        Assert.Equal("Merida", response.BillingContact.Address[1]);
        Assert.Equal("Merida, Merida  VE", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("ula.ve-tec", response.TechnicalContact.RegistryId);
        Assert.Equal("Universidad de los Andes", response.TechnicalContact.Name);
        Assert.Equal("+582127718584", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+582127718599", response.TechnicalContact.FaxNumber);
        Assert.Equal("fobispo@nic.ve", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("ULA", response.TechnicalContact.Address[0]);
        Assert.Equal("Merida", response.TechnicalContact.Address[1]);
        Assert.Equal("Merida, Merida  VE", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("avalon.ula.ve", response.NameServers[0]);
        Assert.Equal("azmodan.ula.ve", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVO", response.DomainStatus[0]);

        Assert.Equal(39, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_nameservers_missing()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "found", "zumba.com.ve.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/04", response.TemplateName);

        Assert.Equal("zumba.com.ve", response.DomainName.ToString());

        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Equal("CON000008238", response.Registrant.RegistryId);
        Assert.Null(response.Registrant.Name);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(0, response.Registrant.Address.Count);


        // AdminContact Details
        Assert.Equal("CON000030857", response.AdminContact.RegistryId);
        Assert.Null(response.AdminContact.Name);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(0, response.AdminContact.Address.Count);


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Equal("CON000030857", response.TechnicalContact.RegistryId);
        Assert.Null(response.TechnicalContact.Name);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(0, response.TechnicalContact.Address.Count);


        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Equal(16, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_activo()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "found", "found_status_activo.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ve/ve/found/01", response.TemplateName);

        Assert.Equal("zumba.com.ve", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("zumba.com.ve-dom", response.Registrant.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.Registrant.Name);
        Assert.Equal("3-97836844", response.Registrant.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.Registrant.Address[0]);
        Assert.Equal("GPO Box 988", response.Registrant.Address[1]);
        Assert.Equal("Melbourne  AU", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("zumba.com.ve-adm", response.AdminContact.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.AdminContact.Name);
        Assert.Equal("3-97831800", response.AdminContact.TelephoneNumber);
        Assert.Equal("3-97836844", response.AdminContact.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.AdminContact.Address[0]);
        Assert.Equal("GPO Box 988", response.AdminContact.Address[1]);
        Assert.Equal("Melbourne  AU", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("zumba.com.ve-bil", response.BillingContact.RegistryId);
        Assert.Equal("Juan Enrique Sanchez Serrano", response.BillingContact.Name);
        Assert.Equal("2691300", response.BillingContact.TelephoneNumber);
        Assert.Equal("3437840", response.BillingContact.FaxNumber);
        Assert.Equal("mail@nameaction.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("NameAction Inc", response.BillingContact.Address[0]);
        Assert.Equal("Av. Providencia 201, Of. 22", response.BillingContact.Address[1]);
        Assert.Equal("Santiago  CL", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("zumba.com.ve-tec", response.TechnicalContact.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.TechnicalContact.Name);
        Assert.Equal("3-97831800", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("3-97836844", response.TechnicalContact.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.TechnicalContact.Address[0]);
        Assert.Equal("GPO Box 988", response.TechnicalContact.Address[1]);
        Assert.Equal("Melbourne  AU", response.TechnicalContact.Address[2]);


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVO", response.DomainStatus[0]);

        Assert.Equal(36, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "not-found", "u34jedzcq.ve.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/06", response.TemplateName);

        Assert.Null(response.DomainName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_suspended()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "suspended", "suspended.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Suspended, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ve/ve/found/01", response.TemplateName);

        Assert.Equal("aloespa.com.ve", response.DomainName.ToString());

        Assert.Equal(new DateTime(2006, 06, 08, 21, 54, 41, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 11, 21, 15, 21, 32, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2010, 11, 21, 15, 21, 32, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("aloespa.com.ve-dom", response.Registrant.RegistryId);
        Assert.Equal("Rafael Perez", response.Registrant.Name);
        Assert.Equal("registro@tepuynet.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Rafael Perez", response.Registrant.Address[0]);
        Assert.Equal("Caracas", response.Registrant.Address[1]);
        Assert.Equal("Caracas, D. Federal  VE", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("aloespa.com.ve-adm", response.AdminContact.RegistryId);
        Assert.Equal("Tepuynet", response.AdminContact.Name);
        Assert.Equal("2418246437", response.AdminContact.TelephoneNumber);
        Assert.Equal("2418246437", response.AdminContact.FaxNumber);
        Assert.Equal("registro@tepuynet.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Tepuynet C.A.", response.AdminContact.Address[0]);
        Assert.Equal("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.AdminContact.Address[1]);
        Assert.Equal("Valencia, Carabobo  VE", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("aloespa.com.ve-bil", response.BillingContact.RegistryId);
        Assert.Equal("Tepuynet", response.BillingContact.Name);
        Assert.Equal("2418246437", response.BillingContact.TelephoneNumber);
        Assert.Equal("2418246437", response.BillingContact.FaxNumber);
        Assert.Equal("registro@tepuynet.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("Tepuynet C.A.", response.BillingContact.Address[0]);
        Assert.Equal("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.BillingContact.Address[1]);
        Assert.Equal("Valencia, Carabobo  VE", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("aloespa.com.ve-tec", response.TechnicalContact.RegistryId);
        Assert.Equal("Tepuynet", response.TechnicalContact.Name);
        Assert.Equal("2418246437", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("2418246437", response.TechnicalContact.FaxNumber);
        Assert.Equal("registro@tepuynet.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Tepuynet C.A.", response.TechnicalContact.Address[0]);
        Assert.Equal("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.TechnicalContact.Address[1]);
        Assert.Equal("Valencia, Carabobo  VE", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns10.tepuyserver.net", response.NameServers[0]);
        Assert.Equal("ns9.tepuyserver.net", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("SUSPENDIDO", response.DomainStatus[0]);

        Assert.Equal(38, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_updated_on()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "found", "found_updated_on.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ve/ve/found/01", response.TemplateName);

        Assert.Equal("ula.ve", response.DomainName.ToString());

        Assert.Equal(new DateTime(2005, 11, 17, 21, 16, 31, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 11, 15, 14, 40, 48, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("ula.ve-dom", response.Registrant.RegistryId);
        Assert.Equal("Universidad de los Andes", response.Registrant.Name);
        Assert.Equal("+582127718584", response.Registrant.TelephoneNumber);
        Assert.Equal("+582127718599", response.Registrant.FaxNumber);
        Assert.Equal("fobispo@nic.ve", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("ULA", response.Registrant.Address[0]);
        Assert.Equal("Merida", response.Registrant.Address[1]);
        Assert.Equal("Merida, Merida  VE", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("ula.ve-adm", response.AdminContact.RegistryId);
        Assert.Equal("Universidad de los Andes", response.AdminContact.Name);
        Assert.Equal("+582127718584", response.AdminContact.TelephoneNumber);
        Assert.Equal("+582127718599", response.AdminContact.FaxNumber);
        Assert.Equal("fobispo@nic.ve", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("ULA", response.AdminContact.Address[0]);
        Assert.Equal("Merida", response.AdminContact.Address[1]);
        Assert.Equal("Merida, Merida  VE", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("ula.ve-bil", response.BillingContact.RegistryId);
        Assert.Equal("Universidad de los Andes", response.BillingContact.Name);
        Assert.Equal("+582127718584", response.BillingContact.TelephoneNumber);
        Assert.Equal("+582127718599", response.BillingContact.FaxNumber);
        Assert.Equal("fobispo@nic.ve", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("ULA", response.BillingContact.Address[0]);
        Assert.Equal("Merida", response.BillingContact.Address[1]);
        Assert.Equal("Merida, Merida  VE", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("ula.ve-tec", response.TechnicalContact.RegistryId);
        Assert.Equal("Universidad de los Andes", response.TechnicalContact.Name);
        Assert.Equal("+582127718584", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+582127718599", response.TechnicalContact.FaxNumber);
        Assert.Equal("fobispo@nic.ve", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("ULA", response.TechnicalContact.Address[0]);
        Assert.Equal("Merida", response.TechnicalContact.Address[1]);
        Assert.Equal("Merida, Merida  VE", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("avalon.ula.ve", response.NameServers[0]);
        Assert.Equal("azmodan.ula.ve", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVO", response.DomainStatus[0]);

        Assert.Equal(39, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_updated_on_blank()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "found", "found_updated_on_blank.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ve/ve/found/01", response.TemplateName);

        Assert.Equal("zumba.com.ve", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("zumba.com.ve-dom", response.Registrant.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.Registrant.Name);
        Assert.Equal("3-97836844", response.Registrant.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.Registrant.Address[0]);
        Assert.Equal("GPO Box 988", response.Registrant.Address[1]);
        Assert.Equal("Melbourne  AU", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("zumba.com.ve-adm", response.AdminContact.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.AdminContact.Name);
        Assert.Equal("3-97831800", response.AdminContact.TelephoneNumber);
        Assert.Equal("3-97836844", response.AdminContact.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.AdminContact.Address[0]);
        Assert.Equal("GPO Box 988", response.AdminContact.Address[1]);
        Assert.Equal("Melbourne  AU", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("zumba.com.ve-bil", response.BillingContact.RegistryId);
        Assert.Equal("Juan Enrique Sanchez Serrano", response.BillingContact.Name);
        Assert.Equal("2691300", response.BillingContact.TelephoneNumber);
        Assert.Equal("3437840", response.BillingContact.FaxNumber);
        Assert.Equal("mail@nameaction.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("NameAction Inc", response.BillingContact.Address[0]);
        Assert.Equal("Av. Providencia 201, Of. 22", response.BillingContact.Address[1]);
        Assert.Equal("Santiago  CL", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("zumba.com.ve-tec", response.TechnicalContact.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.TechnicalContact.Name);
        Assert.Equal("3-97831800", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("3-97836844", response.TechnicalContact.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.TechnicalContact.Address[0]);
        Assert.Equal("GPO Box 988", response.TechnicalContact.Address[1]);
        Assert.Equal("Melbourne  AU", response.TechnicalContact.Address[2]);


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVO", response.DomainStatus[0]);

        Assert.Equal(36, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found_status_available()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "not-found", "not_found_status_available.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ve/ve/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ve", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_inactive()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "inactive", "inactive.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Suspended, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ve/ve/found/01", response.TemplateName);

        Assert.Equal("aloespa-inactive.com.ve", response.DomainName.ToString());

        Assert.Equal(new DateTime(2006, 06, 08, 21, 54, 41, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 11, 21, 15, 21, 32, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2010, 11, 21, 15, 21, 32, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("aloespa-inactive.com.ve-dom", response.Registrant.RegistryId);
        Assert.Equal("Rafael Perez", response.Registrant.Name);
        Assert.Equal("registro@tepuynet.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Rafael Perez", response.Registrant.Address[0]);
        Assert.Equal("Caracas", response.Registrant.Address[1]);
        Assert.Equal("Caracas, D. Federal  VE", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("aloespa-inactive.com.ve-adm", response.AdminContact.RegistryId);
        Assert.Equal("Tepuynet", response.AdminContact.Name);
        Assert.Equal("2418246437", response.AdminContact.TelephoneNumber);
        Assert.Equal("2418246437", response.AdminContact.FaxNumber);
        Assert.Equal("registro@tepuynet.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Tepuynet C.A.", response.AdminContact.Address[0]);
        Assert.Equal("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.AdminContact.Address[1]);
        Assert.Equal("Valencia, Carabobo  VE", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("aloespa-inactive.com.ve-bil", response.BillingContact.RegistryId);
        Assert.Equal("Tepuynet", response.BillingContact.Name);
        Assert.Equal("2418246437", response.BillingContact.TelephoneNumber);
        Assert.Equal("2418246437", response.BillingContact.FaxNumber);
        Assert.Equal("registro@tepuynet.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("Tepuynet C.A.", response.BillingContact.Address[0]);
        Assert.Equal("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.BillingContact.Address[1]);
        Assert.Equal("Valencia, Carabobo  VE", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("aloespa-inactive.com.ve-tec", response.TechnicalContact.RegistryId);
        Assert.Equal("Tepuynet", response.TechnicalContact.Name);
        Assert.Equal("2418246437", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("2418246437", response.TechnicalContact.FaxNumber);
        Assert.Equal("registro@tepuynet.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Tepuynet C.A.", response.TechnicalContact.Address[0]);
        Assert.Equal("Av. Bolivar Norte Torre Banaven, Piso 9 Ofic. 9-9", response.TechnicalContact.Address[1]);
        Assert.Equal("Valencia, Carabobo  VE", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns10.tepuyserver.net", response.NameServers[0]);
        Assert.Equal("ns9.tepuyserver.net", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("SUSPENDIDO", response.DomainStatus[0]);

        Assert.Equal(38, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.ve", "ve", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.ve", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ve/ve/found/01", response.TemplateName);

        Assert.Equal("zumba.com.ve", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 10, 27, 12, 23, 43, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("zumba.com.ve-dom", response.Registrant.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.Registrant.Name);
        Assert.Equal("3-97836844", response.Registrant.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.Registrant.Address[0]);
        Assert.Equal("GPO Box 988", response.Registrant.Address[1]);
        Assert.Equal("Melbourne  AU", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("zumba.com.ve-adm", response.AdminContact.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.AdminContact.Name);
        Assert.Equal("3-97831800", response.AdminContact.TelephoneNumber);
        Assert.Equal("3-97836844", response.AdminContact.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.AdminContact.Address[0]);
        Assert.Equal("GPO Box 988", response.AdminContact.Address[1]);
        Assert.Equal("Melbourne  AU", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("zumba.com.ve-bil", response.BillingContact.RegistryId);
        Assert.Equal("Juan Enrique Sanchez Serrano", response.BillingContact.Name);
        Assert.Equal("2691300", response.BillingContact.TelephoneNumber);
        Assert.Equal("3437840", response.BillingContact.FaxNumber);
        Assert.Equal("mail@nameaction.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("NameAction Inc", response.BillingContact.Address[0]);
        Assert.Equal("Av. Providencia 201, Of. 22", response.BillingContact.Address[1]);
        Assert.Equal("Santiago  CL", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("zumba.com.ve-tec", response.TechnicalContact.RegistryId);
        Assert.Equal("Instra  Corporation Pty Ltd", response.TechnicalContact.Name);
        Assert.Equal("3-97831800", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("3-97836844", response.TechnicalContact.FaxNumber);
        Assert.Equal("instracorp@nameaction.com.ve", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Instra Corporation Pty Ltd", response.TechnicalContact.Address[0]);
        Assert.Equal("GPO Box 988", response.TechnicalContact.Address[1]);
        Assert.Equal("Melbourne  AU", response.TechnicalContact.Address[2]);


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVO", response.DomainStatus[0]);

        Assert.Equal(36, response.FieldsParsed);
    }
}
