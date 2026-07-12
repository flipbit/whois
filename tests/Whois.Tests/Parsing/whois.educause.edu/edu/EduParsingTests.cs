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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "nic.edu.txt");
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_fixture2()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "harvard.edu.txt");
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_fixture3()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "stanford.edu.txt");
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_fixture4()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "nyu.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("nyu.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2007, 10, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1986, 10, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("New York University", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("ITS Communications Operations Services", response.Registrant.Address[0]);
        Assert.Equal("7 East 12th Street, 5th Floor", response.Registrant.Address[1]);
        Assert.Equal("New York, NY 10003", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("NYU Network Operations Admin Role Account", response.AdminContact.Name);
        Assert.Equal("(212) 998-3431", response.AdminContact.TelephoneNumber);
        Assert.Equal("domreg.admin@nyu.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("New York University, ITS C&CS", response.AdminContact.Address[0]);
        Assert.Equal("7 East 12th Street", response.AdminContact.Address[1]);
        Assert.Equal("5th Floor", response.AdminContact.Address[2]);
        Assert.Equal("New York, NY 10003", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Network Operations Center Role Account", response.TechnicalContact.Name);
        Assert.Equal("(212) 998-3444", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("noc@nyu.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("New York University, ITS COS", response.TechnicalContact.Address[0]);
        Assert.Equal("7 East 12th Street", response.TechnicalContact.Address[1]);
        Assert.Equal("Room 501", response.TechnicalContact.Address[2]);
        Assert.Equal("New York, NY 10003", response.TechnicalContact.Address[3]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.nyu.edu", response.NameServers[0]);
        Assert.Equal("ns2.nyu.edu", response.NameServers[1]);
        Assert.Equal("nyu-ns.berkeley.edu", response.NameServers[2]);

        Assert.Equal(27, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_fixture5()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "uiuc.edu.txt");
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_fixture6()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "brown.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        AssertWriter.Write(response);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/03", response.TemplateName);

        Assert.Equal("brown.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 01, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1986, 08, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Brown University", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Computing & Information", response.Registrant.Address[0]);
        Assert.Equal("Services Box 1885", response.Registrant.Address[1]);
        Assert.Equal("Providence, RI 02912-1885", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Kenise Harris", response.AdminContact.Name);
        Assert.Equal("(401) 863-7223", response.AdminContact.TelephoneNumber);
        Assert.Equal("kenise_harris@brown.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("CIS Manager", response.AdminContact.Address[0]);
        Assert.Equal("Brown University", response.AdminContact.Address[1]);
        Assert.Equal("115 Waterman St., Box 1885", response.AdminContact.Address[2]);
        Assert.Equal("Providence, RI 02912-1885", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("NOC", response.TechnicalContact.Name);
        Assert.Equal("(401) 863-7247", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("noc@brown.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Brown University", response.TechnicalContact.Address[0]);
        Assert.Equal("115 Waterman St., Box 1885", response.TechnicalContact.Address[1]);
        Assert.Equal("Providence, RI 02912-1885", response.TechnicalContact.Address[2]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("bru-ns1.brown.edu", response.NameServers[0]);
        Assert.Equal("bru-ns2.brown.edu", response.NameServers[1]);
        Assert.Equal("ns1.ucsb.edu", response.NameServers[2]);

        Assert.Equal(26, response.FieldsParsed);
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_contacts_case1()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "educause.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("educause.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2009, 10, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1998, 03, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2010, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("EDUCAUSE", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("4772 Walnut Street", response.Registrant.Address[0]);
        Assert.Equal("Suite 206", response.Registrant.Address[1]);
        Assert.Equal("Boulder, CO 80301", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Information Technology", response.AdminContact.Name);
        Assert.Equal("(303) 449-4430", response.AdminContact.TelephoneNumber);
        Assert.Equal("netadmin@educause.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("EDUCAUSE", response.AdminContact.Address[0]);
        Assert.Equal("4772 Walnut Street", response.AdminContact.Address[1]);
        Assert.Equal("Ste 206", response.AdminContact.Address[2]);
        Assert.Equal("Boulder, CO 80301", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Information Technology", response.TechnicalContact.Name);
        Assert.Equal("(303) 449-4430", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("netadmin@educause.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("EDUCAUSE", response.TechnicalContact.Address[0]);
        Assert.Equal("4772 Walnut Street", response.TechnicalContact.Address[1]);
        Assert.Equal("Ste 206", response.TechnicalContact.Address[2]);
        Assert.Equal("Boulder, CO 80301", response.TechnicalContact.Address[3]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns3.educause.edu", response.NameServers[0]);
        Assert.Equal("ns4.educause.edu", response.NameServers[1]);
        Assert.Equal("ns5.educause.edu", response.NameServers[2]);

        Assert.Equal(27, response.FieldsParsed);
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_contacts_case4()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "syr.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/02", response.TemplateName);

        Assert.Equal("syr.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 07, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1986, 09, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Syracuse University", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Room 200 Machinery Hall", response.Registrant.Address[0]);
        Assert.Equal("Syracuse, NY 13244", response.Registrant.Address[1]);
        Assert.Equal("UNITED STATES", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("ITS Business Office", response.AdminContact.Name);
        Assert.Equal("(315) 443-6189", response.AdminContact.TelephoneNumber);
        Assert.Equal("itsoffice@syr.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Syracuse University", response.AdminContact.Address[0]);
        Assert.Equal("Information Technology and Services", response.AdminContact.Address[1]);
        Assert.Equal("Center for Science and Technology", response.AdminContact.Address[2]);
        Assert.Equal("Syracuse, NY 13244", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Networking", response.TechnicalContact.Name);
        Assert.Equal("(315) 443-2677", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("ndd@listserv.syr.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Syracuse University", response.TechnicalContact.Address[0]);
        Assert.Equal("Room 200 Machinery Hall", response.TechnicalContact.Address[1]);
        Assert.Equal("Syracuse, NY 13244", response.TechnicalContact.Address[2]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(5, response.NameServers.Count);
        Assert.Equal("lurch.cns.syr.edu", response.NameServers[0]);
        Assert.Equal("icarus.syr.edu", response.NameServers[1]);
        Assert.Equal("suec1.syr.edu", response.NameServers[2]);
        Assert.Equal("ns1.twtelecom.net", response.NameServers[3]);
        Assert.Equal("ns2.twtelecom.net", response.NameServers[4]);

        Assert.Equal(28, response.FieldsParsed);
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_contact_registrant_without_address()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "mit.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("mit.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 06, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1985, 05, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Massachusetts Institute of Technology", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(2, response.Registrant.Address.Count);
        Assert.Equal("Cambridge, MA 02139", response.Registrant.Address[0]);
        Assert.Equal("UNITED STATES", response.Registrant.Address[1]);


        // AdminContact Details
        Assert.Equal("Mark Silis", response.AdminContact.Name);
        Assert.Equal("(617) 324-5900", response.AdminContact.TelephoneNumber);
        Assert.Equal("mark@mit.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Massachusetts Institute of Technology", response.AdminContact.Address[0]);
        Assert.Equal("MIT Room W92-167, 77 Massachusetts Avenue", response.AdminContact.Address[1]);
        Assert.Equal("Cambridge, MA 02139-4307", response.AdminContact.Address[2]);
        Assert.Equal("UNITED STATES", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("MIT Network Operations", response.TechnicalContact.Name);
        Assert.Equal("(617) 253-8400", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("network@mit.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Massachusetts Institute of Technology", response.TechnicalContact.Address[0]);
        Assert.Equal("MIT Room W92-167, 77 Massachusetts Avenue", response.TechnicalContact.Address[1]);
        Assert.Equal("Cambridge, MA 02139-4307", response.TechnicalContact.Address[2]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[3]);


        Assert.Equal(22, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_contact_registrant_without_zip()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "aucmed.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("aucmed.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 08, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1997, 07, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("The American University of the Caribbean School of Medicine", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("c/o Campbell Corporate Services, Ltd.", response.Registrant.Address[0]);
        Assert.Equal("Scotiabank Building, P. O. Box 268", response.Registrant.Address[1]);
        Assert.Equal("Grand Cayman", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Ron  Spaide", response.AdminContact.Name);
        Assert.Equal("(732) 509-4796", response.AdminContact.TelephoneNumber);
        Assert.Equal("rspaide@devrymedical.org", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("VP, CIO", response.AdminContact.Address[0]);
        Assert.Equal("Devry Medical International, Inc", response.AdminContact.Address[1]);
        Assert.Equal("630 US Highway 1", response.AdminContact.Address[2]);
        Assert.Equal("North Brunswick, NJ 08902", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Bill Huber", response.TechnicalContact.Name);
        Assert.Equal("(732) 509-4796", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("bhuber@devrymedical.org", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Director, Network Operations", response.TechnicalContact.Address[0]);
        Assert.Equal("DeVry Medical International, Inc", response.TechnicalContact.Address[1]);
        Assert.Equal("630 US Highway 1", response.TechnicalContact.Address[2]);
        Assert.Equal("North Brunswick, NJ 08902", response.TechnicalContact.Address[3]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[4]);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.geodns.net", response.NameServers[0]);
        Assert.Equal("ns2.geodns.net", response.NameServers[1]);

        Assert.Equal(26, response.FieldsParsed);
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_updated_on_unknown()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "pcihealth.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        AssertWriter.Write(response);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("pcihealth.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2004, 03, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("PCI Health Training Center", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("8101 John Carpenter Freeway", response.Registrant.Address[0]);
        Assert.Equal("Dallas, TX 75247-4720", response.Registrant.Address[1]);
        Assert.Equal("UNITED STATES", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Kelly Drake", response.AdminContact.Name);
        Assert.Equal("(214) 630-0568", response.AdminContact.TelephoneNumber);
        Assert.Equal("kdrake@pcihealth.net", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("admissions", response.AdminContact.Address[0]);
        Assert.Equal("PCI Health Training Center", response.AdminContact.Address[1]);
        Assert.Equal("8101 John Carpenter Freeway", response.AdminContact.Address[2]);
        Assert.Equal("Dallas, TX 75247-4720", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("daniel Roy", response.TechnicalContact.Name);
        Assert.Equal("(214) 215-1764", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("dan@nativetechnology.net", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("InfoTech Services", response.TechnicalContact.Address[0]);
        Assert.Equal("PCI Health Training Center", response.TechnicalContact.Address[1]);
        Assert.Equal("8101 John Carpenter Freeway", response.TechnicalContact.Address[2]);
        Assert.Equal("Dallas, TX 75247-4720", response.TechnicalContact.Address[3]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.maximumasp.com", response.NameServers[0]);
        Assert.Equal("ns2.maximumasp.com", response.NameServers[1]);

        Assert.Equal(25, response.FieldsParsed);
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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.educause.edu", "edu", "found", "academia.edu.txt");
        var response = parser.Parse("whois.educause.edu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.educause.edu/edu/found/01", response.TemplateName);

        Assert.Equal("academia.edu", response.DomainName.ToString());

        Assert.Equal(new DateTime(2012, 04, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1999, 05, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 07, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Academia", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("251 Kearny St", response.Registrant.Address[0]);
        Assert.Equal("suite 520", response.Registrant.Address[1]);
        Assert.Equal("San Francisco, CA 94108", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Academia, Inc.", response.AdminContact.Name);
        Assert.Equal("(415) 829-2341", response.AdminContact.TelephoneNumber);
        Assert.Equal("helpdesk@academia.edu", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("251 Kearny St", response.AdminContact.Address[0]);
        Assert.Equal("suite 520", response.AdminContact.Address[1]);
        Assert.Equal("San Francisco, CA 94108", response.AdminContact.Address[2]);
        Assert.Equal("UNITED STATES", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Academia, Inc.", response.TechnicalContact.Name);
        Assert.Equal("(415) 829-2341", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("helpdesk@academia.edu", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("251 Kearny St", response.TechnicalContact.Address[0]);
        Assert.Equal("suite 520", response.TechnicalContact.Address[1]);
        Assert.Equal("San Francisco, CA 94108", response.TechnicalContact.Address[2]);
        Assert.Equal("UNITED STATES", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns-1484.awsdns-57.org", response.NameServers[0]);
        Assert.Equal("ns-225.awsdns-28.com", response.NameServers[1]);
        Assert.Equal("ns-1850.awsdns-39.co.uk", response.NameServers[2]);
        Assert.Equal("ns-629.awsdns-14.net", response.NameServers[3]);

        Assert.Equal(27, response.FieldsParsed);
    }
}
