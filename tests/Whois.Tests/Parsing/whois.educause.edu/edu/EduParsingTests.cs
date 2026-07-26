using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Educause.Edu.Edu;

public class EduParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public EduParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "nic.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("nic.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address

        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_fixture2()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "harvard.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("harvard.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_fixture3()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "stanford.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("stanford.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address

        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_fixture4()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "nyu.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("nyu.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_fixture5()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "uiuc.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("uiuc.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_fixture6()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "brown.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("brown.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contacts()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "found_contacts.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("nic.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 06, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1996, 12, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("North Idaho College", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("1000 W. Garden Avenue", response.Registrant.Address[0]);
        Assert.Equal("Coeur d'Alene, ID 83814", response.Registrant.Address[1]);
        Assert.Equal("UNITED STATES", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("NetAdmin", response.AdminContact.Name);
        Assert.Equal("(208) 769-7860", response.AdminContact.TelephoneNumber);
        Assert.Equal("netsys@nic.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("North Idaho College", response.AdminContact.Address[0]);
        Assert.Equal("1000 W. Garden Avenue", response.AdminContact.Address[1]);
        Assert.Equal("Coeur d Alene, ID 83814", response.AdminContact.Address[2]);
        Assert.Equal("UNITED STATES", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Dennis L Noordam", response.TechnicalContact.Name);
        Assert.Equal("(208) 769-7860", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("dlnoordam@nic.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Windows System Administrator", response.TechnicalContact.Address[0]);
        Assert.Equal("North Idaho College", response.TechnicalContact.Address[1]);
        Assert.Equal("1000 W. Garden Avenue", response.TechnicalContact.Address[2]);
        Assert.Equal("Coeur d Alene, ID 83814", response.TechnicalContact.Address[3]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("nicns1.nic.edu", response.NameServers[0]);
        Assert.Equal("nicns2.nic.edu", response.NameServers[1]);

        Assert.Equal(26, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contacts_case1()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "educause.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("educause.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contacts_case2()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "found_contacts_case2.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("stanford.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2009, 05, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1985, 10, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Stanford University", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("The Board of Trustees of the Leland Stanford Junior University", response.Registrant.Address[0]);
        Assert.Equal("241 Panama Street, Pine Hall, Room 115", response.Registrant.Address[1]);
        Assert.Equal("Stanford, CA 94305-4122", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Domain Admin", response.AdminContact.Name);
        Assert.Equal("(650) 723-4328", response.AdminContact.TelephoneNumber);
        Assert.Equal("sunet-admin@stanford.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Stanford University", response.AdminContact.Address[0]);
        Assert.Equal("241 Panama Street Pine Hall, Room 115", response.AdminContact.Address[1]);
        Assert.Equal("Stanford, CA 94305-4122", response.AdminContact.Address[2]);
        Assert.Equal("UNITED STATES", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Domain Admin", response.TechnicalContact.Name);
        Assert.Equal("(650) 723-4328", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("sunet-admin@stanford.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Stanford University", response.TechnicalContact.Address[0]);
        Assert.Equal("241 Panama Street Pine Hall, Room 115", response.TechnicalContact.Address[1]);
        Assert.Equal("Stanford, CA 94305-4122", response.TechnicalContact.Address[2]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("argus.stanford.edu", response.NameServers[0]);
        Assert.Equal("avallone.stanford.edu", response.NameServers[1]);
        Assert.Equal("atalante.stanford.edu", response.NameServers[2]);
        Assert.Equal("aerathea.stanford.edu", response.NameServers[3]);

        Assert.Equal(27, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contacts_case3()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "found_contacts_case3.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("uiuc.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 03, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1985, 07, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("University of Illinois at Urbana Champaign", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("CITES 1120 Digital Computer Laboratory", response.Registrant.Address[0]);
        Assert.Equal("1304 West Springfield Avenue", response.Registrant.Address[1]);
        Assert.Equal("Urbana, IL 61801-2910", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Tracy L. Smith", response.AdminContact.Name);
        Assert.Equal("(217) 244-2032", response.AdminContact.TelephoneNumber);
        Assert.Equal("edu-admin@listserv.illinois.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("University of Illinois at Urbana-Champaign", response.AdminContact.Address[0]);
        Assert.Equal("CITES  2105 Digital Computer Laboratory", response.AdminContact.Address[1]);
        Assert.Equal("1304 West Springfield Avenue", response.AdminContact.Address[2]);
        Assert.Equal("Urbana, IL 61801-4399", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Charles Kline", response.TechnicalContact.Name);
        Assert.Equal("(217) 333-3339", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("edu-tech@listserv.illinois.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("University of Illinois at Urbana Champaign", response.TechnicalContact.Address[0]);
        Assert.Equal("CITES 1120 Digital Computer Laboratory", response.TechnicalContact.Address[1]);
        Assert.Equal("1304 West Springfield Avenue", response.TechnicalContact.Address[2]);
        Assert.Equal("Urbana, IL 61801", response.TechnicalContact.Address[3]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("dns1.illinois.edu", response.NameServers[0]);
        Assert.Equal("dns2.illinois.edu", response.NameServers[1]);
        Assert.Equal("dns1.iu.edu", response.NameServers[2]);

        Assert.Equal(27, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contacts_case4()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "syr.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("syr.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contact_registrant()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "found_contact_registrant.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("nic.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 06, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1996, 12, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("North Idaho College", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("1000 W. Garden Avenue", response.Registrant.Address[0]);
        Assert.Equal("Coeur d'Alene, ID 83814", response.Registrant.Address[1]);
        Assert.Equal("UNITED STATES", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("NetAdmin", response.AdminContact.Name);
        Assert.Equal("(208) 769-7860", response.AdminContact.TelephoneNumber);
        Assert.Equal("netsys@nic.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("North Idaho College", response.AdminContact.Address[0]);
        Assert.Equal("1000 W. Garden Avenue", response.AdminContact.Address[1]);
        Assert.Equal("Coeur d Alene, ID 83814", response.AdminContact.Address[2]);
        Assert.Equal("UNITED STATES", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Dennis L Noordam", response.TechnicalContact.Name);
        Assert.Equal("(208) 769-7860", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("dlnoordam@nic.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Windows System Administrator", response.TechnicalContact.Address[0]);
        Assert.Equal("North Idaho College", response.TechnicalContact.Address[1]);
        Assert.Equal("1000 W. Garden Avenue", response.TechnicalContact.Address[2]);
        Assert.Equal("Coeur d Alene, ID 83814", response.TechnicalContact.Address[3]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("nicns1.nic.edu", response.NameServers[0]);
        Assert.Equal("nicns2.nic.edu", response.NameServers[1]);

        Assert.Equal(26, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contact_registrant_without_address()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "mit.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("mit.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contact_registrant_without_zip()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "aucmed.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("aucmed.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address

        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contact_registrant_with_additional_organization()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "found_contact_registrant_with_additional_organization.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("harvard.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2012, 03, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1985, 06, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Harvard University", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("HUIT Network Services", response.Registrant.Address[0]);
        Assert.Equal("60 Oxford Street", response.Registrant.Address[1]);
        Assert.Equal("Cambridge, MA 02138", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Jacques N Laflamme", response.AdminContact.Name);
        Assert.Equal("(617) 384-6663", response.AdminContact.TelephoneNumber);
        Assert.Equal("jacques_laflamme@harvard.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Director, Network Services", response.AdminContact.Address[0]);
        Assert.Equal("Harvard University", response.AdminContact.Address[1]);
        Assert.Equal("60 Oxford Street", response.AdminContact.Address[2]);
        Assert.Equal("Cambridge, MA 02138", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Network Operations", response.TechnicalContact.Name);
        Assert.Equal("(617) 495-7777", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("netmanager@harvard.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Harvard University", response.TechnicalContact.Address[0]);
        Assert.Equal("HUIT Network Services", response.TechnicalContact.Address[1]);
        Assert.Equal("60 Oxford Street", response.TechnicalContact.Address[2]);
        Assert.Equal("Cambridge, MA 02138", response.TechnicalContact.Address[3]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("externaldns-c1.harvard.edu", response.NameServers[0]);
        Assert.Equal("externaldns-c2.harvard.edu", response.NameServers[1]);
        Assert.Equal("externaldns-c3.br.harvard.edu", response.NameServers[2]);

        Assert.Equal(27, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_updated_on_unknown()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "pcihealth.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("pcihealth.edu", response.DomainName.ToString());

        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "not-found", "not_found.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "academia.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("academia.edu", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }
}
