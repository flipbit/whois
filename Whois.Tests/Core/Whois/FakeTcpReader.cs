using System.Collections;
using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois
{
    /// <summary>
    /// Fakes out TCP responses for testing
    /// </summary>
    internal class FakeTcpReader : ITcpReader
    {
        public ArrayList Read(string url, int port, string command)
        {
            var response = new ArrayList();

            switch (command)
            {
                case "cogworks.co.uk":
                    response.AddRange(FakeCogworksResponse.Split('\n'));
                    break;

                case "google.com":
                    response.AddRange(url == "whois.markmonitor.com" ? FakeGoogleResponse3.Split('\n') : FakeGoogleResponse1.Split('\n'));
                    break;

                case "=google.com":
                    response.AddRange(FakeGoogleResponse2.Split('\n'));
                    break;
            };

            return response;
        }

        public void Dispose()
        {
        }

        #region Contants

        // Retrieved 7th July, 2009
        public const string FakeCogworksResponse =
            @"    Domain name:
        cogworks.co.uk

    Registrant:
        Chris Wood

    Registrant type:
        UK Individual

    Registrant's address:
        The registrant is a non-trading individual who has opted to have their
        address omitted from the WHOIS service.

    Registrar:
        1 & 1 Internet AG [Tag = SCHLUND]
        URL: http://registrar.1und1.info

    Relevant dates:
        Registered on: 26-Aug-2003
        Renewal date:  26-Aug-2009
        Last updated:  07-Apr-2009

    Registration status:
        Registered until renewal date.

    Name servers:
        ns59.1and1.co.uk
        ns60.1and1.co.uk

    WHOIS lookup made at 13:53:10 07-Jun-2009

-- 
This WHOIS information is provided for free by Nominet UK the central registry
for .uk domain names. This information and the .uk WHOIS are:

    Copyright Nominet UK 1996 - 2009.

You may not access the .uk WHOIS or use any data from it except as permitted
by the terms of use available in full at http://www.nominet.org.uk/whois, which
includes restrictions on: (A) use of the data for advertising, or its
repackaging, recompilation, redistribution or reuse (B) obscuring, removing
or hiding any or all of this notice and (C) exceeding query rate or volume
limits. The data is provided on an 'as-is' basis and may lag behind the
register. Access may be withdrawn or restricted at any time. ";

        public const string FakeGoogleResponse1 = @"Whois Server Version 2.0

Domain names in the .com and .net domains can now be registered
with many different competing registrars. Go to http://www.internic.net
for detailed information.

GOOGLE.COM.ZZZZZ.GET.LAID.AT.WWW.SWINGINGCOMMUNITY.COM
GOOGLE.COM.ZZZZZ.DOWNLOAD.MOVIE.ONLINE.ZML2.COM
GOOGLE.COM.ZOMBIED.AND.HACKED.BY.WWW.WEB-HACK.COM
GOOGLE.COM.ZNAET.PRODOMEN.COM
GOOGLE.COM.WORDT.DOOR.VEEL.WHTERS.GEBRUIKT.SERVERTJE.NET
GOOGLE.COM.VN
GOOGLE.COM.UY
GOOGLE.COM.UA
GOOGLE.COM.TW
GOOGLE.COM.TR
GOOGLE.COM.SUCKS.FIND.CRACKZ.WITH.SEARCH.GULLI.COM
GOOGLE.COM.SPROSIUYANDEKSA.RU
GOOGLE.COM.SERVES.PR0N.FOR.ALLIYAH.NET
GOOGLE.COM.SA
GOOGLE.COM.PLZ.GIVE.A.PR8.TO.AUDIOTRACKER.NET
GOOGLE.COM.MX
GOOGLE.COM.IS.SHIT.SQUAREBOARDS.COM
GOOGLE.COM.IS.NOT.HOSTED.BY.ACTIVEDOMAINDNS.NET
GOOGLE.COM.IS.HOSTED.ON.PROFITHOSTING.NET
GOOGLE.COM.IS.APPROVED.BY.NUMEA.COM
GOOGLE.COM.HAS.LESS.FREE.PORN.IN.ITS.SEARCH.ENGINE.THAN.SECZY.COM
GOOGLE.COM.DO
GOOGLE.COM.COLLEGELEARNER.COM
GOOGLE.COM.CO
GOOGLE.COM.BR
GOOGLE.COM.BEYONDWHOIS.COM
GOOGLE.COM.AU
GOOGLE.COM.ACQUIRED.BY.CALITEC.NET
GOOGLE.COM

To single out one record, look it up with ""xxx"", where xxx is one of the
of the records displayed above. If the records are the same, look them up
with ""=xxx"" to receive a full display for each record.

>>> Last update of whois database: Sun, 07 Jun 2009 12:58:04 UTC <<<

NOTICE: The expiration date displayed in this record is the date the 
registrar's sponsorship of the domain name registration in the registry is 
currently set to expire. This date does not necessarily reflect the expiration 
date of the domain name registrant's agreement with the sponsoring 
registrar.  Users may consult the sponsoring registrar's Whois database to 
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois 
database through the use of electronic processes that are high-volume and 
automated except as reasonably necessary to register domain names or 
modify existing registrations; the Data in VeriSign Global Registry 
Services' (""VeriSign"") Whois database is provided by VeriSign for 
information purposes only, and to assist persons in obtaining information 
about or related to a domain name registration record. VeriSign does not 
guarantee its accuracy. By submitting a Whois query, you agree to abide 
by the following terms of use: You agree that you may use this Data only 
for lawful purposes and that under no circumstances will you use this Data 
to: (1) allow, enable, or otherwise support the transmission of mass 
unsolicited, commercial advertising or solicitations via e-mail, telephone, 
or facsimile; or (2) enable high volume, automated, electronic processes 
that apply to VeriSign (or its computer systems). The compilation, 
repackaging, dissemination or other use of this Data is expressly 
prohibited without the prior written consent of VeriSign. You agree not to 
use electronic processes that are automated and high-volume to access or 
query the Whois database except as reasonably necessary to register 
domain names or modify existing registrations. VeriSign reserves the right 
to restrict your access to the Whois database in its sole discretion to ensure 
operational stability.  VeriSign may restrict or terminate your access to the 
Whois database for failure to abide by these terms of use. VeriSign 
reserves the right to modify these terms at any time. 

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
";
        /// <summary>
        /// Response from WHOIS server for Google.com after expanding the search results.
        /// (includes actual whois server names)
        /// </summary>
        public const string FakeGoogleResponse2 = @"
Whois Server Version 2.0

Domain names in the .com and .net domains can now be registered
with many different competing registrars. Go to http://www.internic.net
for detailed information.

   Server Name: GOOGLE.COM.ZZZZZ.GET.LAID.AT.WWW.SWINGINGCOMMUNITY.COM
   IP Address: 69.41.185.195
   Registrar: TUCOWS INC.
   Whois Server: whois.tucows.com
   Referral URL: http://domainhelp.opensrs.net

   Server Name: GOOGLE.COM.ZZZZZ.DOWNLOAD.MOVIE.ONLINE.ZML2.COM
   IP Address: 64.28.187.63
   Registrar: DIRECTI INTERNET SOLUTIONS PVT. LTD. D/B/A PUBLICDOMAINREGISTRY.COM
   Whois Server: whois.PublicDomainRegistry.com
   Referral URL: http://www.PublicDomainRegistry.com

   Server Name: GOOGLE.COM.ZOMBIED.AND.HACKED.BY.WWW.WEB-HACK.COM
   IP Address: 217.107.217.167
   Registrar: DOMAINCONTEXT, INC.
   Whois Server: whois.domaincontext.com
   Referral URL: http://www.domaincontext.com

   Server Name: GOOGLE.COM.ZNAET.PRODOMEN.COM
   IP Address: 62.149.23.126
   Registrar: DIRECTI INTERNET SOLUTIONS PVT. LTD. D/B/A PUBLICDOMAINREGISTRY.COM
   Whois Server: whois.PublicDomainRegistry.com
   Referral URL: http://www.PublicDomainRegistry.com

   Server Name: GOOGLE.COM.WORDT.DOOR.VEEL.WHTERS.GEBRUIKT.SERVERTJE.NET
   IP Address: 62.41.27.144
   Registrar: KEY-SYSTEMS GMBH
   Whois Server: whois.rrpproxy.net
   Referral URL: http://www.key-systems.net

   Server Name: GOOGLE.COM.VN
   Registrar: ONLINENIC, INC.
   Whois Server: whois.onlinenic.com
   Referral URL: http://www.OnlineNIC.com

   Server Name: GOOGLE.COM.UY
   Registrar: DIRECTI INTERNET SOLUTIONS PVT. LTD. D/B/A PUBLICDOMAINREGISTRY.COM
   Whois Server: whois.PublicDomainRegistry.com
   Referral URL: http://www.PublicDomainRegistry.com

   Server Name: GOOGLE.COM.UA
   Registrar: DIRECTI INTERNET SOLUTIONS PVT. LTD. D/B/A PUBLICDOMAINREGISTRY.COM
   Whois Server: whois.PublicDomainRegistry.com
   Referral URL: http://www.PublicDomainRegistry.com

   Server Name: GOOGLE.COM.TW
   Registrar: WEB COMMERCE COMMUNICATIONS LIMITED DBA WEBNIC.CC
   Whois Server: whois.webnic.cc
   Referral URL: http://www.webnic.cc

   Server Name: GOOGLE.COM.TR
   Registrar: DIRECTI INTERNET SOLUTIONS PVT. LTD. D/B/A PUBLICDOMAINREGISTRY.COM
   Whois Server: whois.PublicDomainRegistry.com
   Referral URL: http://www.PublicDomainRegistry.com

   Server Name: GOOGLE.COM.SUCKS.FIND.CRACKZ.WITH.SEARCH.GULLI.COM
   IP Address: 80.190.192.24
   Registrar: EPAG DOMAINSERVICES GMBH
   Whois Server: whois.enterprice.net
   Referral URL: http://www.enterprice.net

   Server Name: GOOGLE.COM.SPROSIUYANDEKSA.RU
   Registrar: MELBOURNE IT, LTD. D/B/A INTERNET NAMES WORLDWIDE
   Whois Server: whois.melbourneit.com
   Referral URL: http://www.melbourneit.com

   Server Name: GOOGLE.COM.SERVES.PR0N.FOR.ALLIYAH.NET
   IP Address: 84.255.209.69
   Registrar: GODADDY.COM, INC.
   Whois Server: whois.godaddy.com
   Referral URL: http://registrar.godaddy.com

   Server Name: GOOGLE.COM.SA
   Registrar: OMNIS NETWORK, LLC
   Whois Server: whois.omnis.com
   Referral URL: http://domains.omnis.com

   Server Name: GOOGLE.COM.PLZ.GIVE.A.PR8.TO.AUDIOTRACKER.NET
   IP Address: 213.251.184.30
   Registrar: OVH
   Whois Server: whois.ovh.com
   Referral URL: http://www.ovh.com

   Server Name: GOOGLE.COM.MX
   Registrar: DIRECTI INTERNET SOLUTIONS PVT. LTD. D/B/A PUBLICDOMAINREGISTRY.COM
   Whois Server: whois.PublicDomainRegistry.com
   Referral URL: http://www.PublicDomainRegistry.com

   Server Name: GOOGLE.COM.IS.SHIT.SQUAREBOARDS.COM
   IP Address: 203.170.84.81
   Registrar: AUST DOMAINS INTERNATIONAL PTY LTD DBA AUST DOMAINS, INC.
   Whois Server: whois.syra.com.au
   Referral URL: http://www.syra.com.au

   Server Name: GOOGLE.COM.IS.NOT.HOSTED.BY.ACTIVEDOMAINDNS.NET
   IP Address: 217.148.161.5
   Registrar: ENOM, INC.
   Whois Server: whois.enom.com
   Referral URL: http://www.enom.com

   Server Name: GOOGLE.COM.IS.HOSTED.ON.PROFITHOSTING.NET
   IP Address: 66.49.213.213
   Registrar: NAME.COM LLC
   Whois Server: whois.name.com
   Referral URL: http://www.name.com

   Server Name: GOOGLE.COM.IS.APPROVED.BY.NUMEA.COM
   IP Address: 213.228.0.43
   Registrar: GANDI SAS
   Whois Server: whois.gandi.net
   Referral URL: http://www.gandi.net

   Server Name: GOOGLE.COM.HAS.LESS.FREE.PORN.IN.ITS.SEARCH.ENGINE.THAN.SECZY.COM
   IP Address: 209.187.114.130
   Registrar: TUCOWS INC.
   Whois Server: whois.tucows.com
   Referral URL: http://domainhelp.opensrs.net

   Server Name: GOOGLE.COM.DO
   Registrar: GODADDY.COM, INC.
   Whois Server: whois.godaddy.com
   Referral URL: http://registrar.godaddy.com

   Server Name: GOOGLE.COM.COLLEGELEARNER.COM
   IP Address: 72.14.207.99
   IP Address: 64.233.187.99
   IP Address: 64.233.167.99
   Registrar: GODADDY.COM, INC.
   Whois Server: whois.godaddy.com
   Referral URL: http://registrar.godaddy.com

   Server Name: GOOGLE.COM.CO
   Registrar: NAMESECURE.COM
   Whois Server: whois.namesecure.com
   Referral URL: http://www.namesecure.com

   Server Name: GOOGLE.COM.BR
   Registrar: ENOM, INC.
   Whois Server: whois.enom.com
   Referral URL: http://www.enom.com

   Server Name: GOOGLE.COM.BEYONDWHOIS.COM
   IP Address: 203.36.226.2
   Registrar: TUCOWS INC.
   Whois Server: whois.tucows.com
   Referral URL: http://domainhelp.opensrs.net

   Server Name: GOOGLE.COM.AU
   Registrar: PLANETDOMAIN PTY LTD.
   Whois Server: whois.planetdomain.com
   Referral URL: http://www.planetdomain.com

   Server Name: GOOGLE.COM.ACQUIRED.BY.CALITEC.NET
   IP Address: 85.190.27.2
   Registrar: ENOM, INC.
   Whois Server: whois.enom.com
   Referral URL: http://www.enom.com

   Domain Name: GOOGLE.COM
   Registrar: MARKMONITOR INC.
   Whois Server: whois.markmonitor.com
   Referral URL: http://www.markmonitor.com
   Name Server: NS1.GOOGLE.COM
   Name Server: NS2.GOOGLE.COM
   Name Server: NS3.GOOGLE.COM
   Name Server: NS4.GOOGLE.COM
   Status: clientDeleteProhibited
   Status: clientTransferProhibited
   Status: clientUpdateProhibited
   Status: serverDeleteProhibited
   Status: serverTransferProhibited
   Status: serverUpdateProhibited
   Updated Date: 18-nov-2008
   Creation Date: 15-sep-1997
   Expiration Date: 14-sep-2011

>>> Last update of whois database: Sun, 07 Jun 2009 12:49:38 UTC <<<

NOTICE: The expiration date displayed in this record is the date the 
registrar's sponsorship of the domain name registration in the registry is 
currently set to expire. This date does not necessarily reflect the expiration 
date of the domain name registrant's agreement with the sponsoring 
registrar.  Users may consult the sponsoring registrar's Whois database to 
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois 
database through the use of electronic processes that are high-volume and 
automated except as reasonably necessary to register domain names or 
modify existing registrations; the Data in VeriSign Global Registry 
Services' (""VeriSign"") Whois database is provided by VeriSign for 
information purposes only, and to assist persons in obtaining information 
about or related to a domain name registration record. VeriSign does not 
guarantee its accuracy. By submitting a Whois query, you agree to abide 
by the following terms of use: You agree that you may use this Data only 
for lawful purposes and that under no circumstances will you use this Data 
to: (1) allow, enable, or otherwise support the transmission of mass 
unsolicited, commercial advertising or solicitations via e-mail, telephone, 
or facsimile; or (2) enable high volume, automated, electronic processes 
that apply to VeriSign (or its computer systems). The compilation, 
repackaging, dissemination or other use of this Data is expressly 
prohibited without the prior written consent of VeriSign. You agree not to 
use electronic processes that are automated and high-volume to access or 
query the Whois database except as reasonably necessary to register 
domain names or modify existing registrations. VeriSign reserves the right 
to restrict your access to the Whois database in its sole discretion to ensure 
operational stability.  VeriSign may restrict or terminate your access to the 
Whois database for failure to abide by these terms of use. VeriSign 
reserves the right to modify these terms at any time. 

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
";
        public const string FakeGoogleResponse3 = @"-----------------------------------------------------------------------
MarkMonitor, the Global Leader in Enterprise Brand Protection

Domain Management
Online Trademark Protection
Online Channel Protection
AntiPhishing Solutions
-----------------------------------------------------------------------
The Data in MarkMonitor.com's WHOIS database is provided by MarkMonitor.com
for information purposes, and to assist persons in obtaining information
about or related to a domain name registration record.  MarkMonitor.com
does not guarantee its accuracy.  By submitting a WHOIS query, you agree
that you will use this Data only for lawful purposes and that, under no
circumstances will you use this Data to: (1) allow, enable, or otherwise
support the transmission of mass unsolicited, commercial advertising or
solicitations via e-mail (spam); or  (2) enable high volume, automated,
electronic processes that apply to MarkMonitor.com (or its systems).
MarkMonitor.com reserves the right to modify these terms at any time.
By submitting this query, you agree to abide by this policy.

Registrant:
        Dns Admin
        Google Inc.
        Please contact contact-admin@google.com 1600 Amphitheatre Parkway
         Mountain View CA 94043
        US
        dns-admin@google.com +1.6502530000 Fax: +1.6506188571

    Domain Name: google.com

        Registrar Name: Markmonitor.com
        Registrar Whois: whois.markmonitor.com
        Registrar Homepage: http://www.markmonitor.com

    Administrative Contact:
        DNS Admin
        Google Inc.
        1600 Amphitheatre Parkway
         Mountain View CA 94043
        US
        dns-admin@google.com +1.6506234000 Fax: +1.6506188571
    Technical Contact, Zone Contact:
        DNS Admin
        Google Inc.
        2400 E. Bayshore Pkwy
         Mountain View CA 94043
        US
        dns-admin@google.com +1.6503300100 Fax: +1.6506181499

    Created on..............: 1997-09-15.
    Expires on..............: 2011-09-13.
    Record last updated on..: 2008-06-08.

    Domain servers in listed order:

    ns3.google.com
    ns2.google.com
    ns4.google.com
    ns1.google.com
    



-----------------------------------------------------------------------
MarkMonitor, the Global Leader in Enterprise Brand Protection

Domain Management
Online Trademark Protection
Online Channel Protection
AntiPhishing Solutions
-----------------------------------------------------------------------
--
";

        public const string FakeYaRuResponse =
            @"% By submitting a query to RIPN's Whois Service
% you agree to abide by the following terms of use:
% http://www.ripn.net/about/servpol.html#3.2 (in Russian)
% http://www.ripn.net/about/en/servpol.html#3.2 (in English).

domain:     YA.RU
type:       CORPORATE
nserver:    ns1.yandex.ru.
nserver:    ns5.yandex.ru.
state:      REGISTERED, DELEGATED
org:        YANDEX, LLC.
phone:      +7 495 7397000
fax-no:     +7 495 7397070
e-mail:     noc@yandex.net
registrar:  RUCENTER-REG-RIPN
created:    1999.07.12
paid-till:  2009.08.01
source:     TC-RIPN


Last updated on 2009.06.12 18:12:58 MSK/MSD";

        #endregion
    }
}