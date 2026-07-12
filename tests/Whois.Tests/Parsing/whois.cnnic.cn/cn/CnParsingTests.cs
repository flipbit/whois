using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cnnic.Cn.Cn;

public class CnParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CnParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.cnnic.cn", "cn", "found", "concordecals.com.cn.txt");
        var response = parser.Parse("whois.cnnic.cn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cnnic.cn/cn/found/01", response.TemplateName);

        Assert.Equal("concordecals.com.cn", response.DomainName.ToString());
        Assert.Equal("20021209s10011s00041927-cn", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("商中在线科技股份有限公司", response.Registrar.Name);

        Assert.Equal(new DateTime(2002, 3, 6, 0, 0, 0), response.Registered);
        Assert.Equal(new DateTime(2028, 3, 6, 0, 0, 0), response.Expiration);

        // Registrant Details
        Assert.Equal("惠州市汇浩工艺品有限公司", response.Registrant.Name);
        Assert.Null(response.Registrant.Organization);

        // AdminContact Details
        Assert.Null(response.AdminContact);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.dns.com.cn", response.NameServers[0]);
        Assert.Equal("ns2.dns.com.cn", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(11, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.cnnic.cn", "cn", "reserved", "reserved.txt");
        var response = parser.Parse("whois.cnnic.cn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cnnic.cn/cn/reserved/02", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.cnnic.cn", "cn", "not-found", "not_found.txt");
        var response = parser.Parse("whois.cnnic.cn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cnnic.cn/cn/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.cnnic.cn", "cn", "found", "google.cn.txt");
        var response = parser.Parse("whois.cnnic.cn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cnnic.cn/cn/found/01", response.TemplateName);

        Assert.Equal("google.cn", response.DomainName.ToString());
        Assert.Equal("20030311s10001s00033735-cn", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("厦门易名科技股份有限公司", response.Registrar.Name);

        Assert.Equal(new DateTime(2003, 3, 17, 12, 20, 5), response.Registered);
        Assert.Equal(new DateTime(2027, 3, 17, 12, 48, 36), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant.RegistryId);
        Assert.Equal("北京谷翔信息技术有限公司", response.Registrant.Name);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns2.google.com", response.NameServers[0]);
        Assert.Equal("ns1.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(5, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("serverUpdateProhibited", response.DomainStatus[2]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[3]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[4]);

        Assert.Equal(17, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved_status_reserved()
    {
        var sample = SampleReader.Read("whois.cnnic.cn", "cn", "reserved", "reserved_status_reserved.txt");
        var response = parser.Parse("whois.cnnic.cn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cnnic.cn/cn/reserved/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_025bbs_cn()
    {
        var sample = SampleReader.Read("whois.cnnic.cn", "cn", "found", "025bbs.cn.txt");

        var record = parser.Parse("whois.cnnic.cn", sample);

        Assert.Equal("20180313s10001s99456578-cn", record.RegistryDomainId);
        Assert.Equal("阿里云计算有限公司（万网）", record.Registrar.Name);
        Assert.Equal(new DateTime(2018, 3, 13, 21, 45, 16), record.Registered!.Value.ToUniversalTime());
        Assert.Equal(new DateTime(2021, 3, 13, 21, 45, 16), record.Expiration!.Value.ToUniversalTime());
        Assert.Equal("南京越之彬网络科技有限公司", record.Registrant.Name);
        Assert.Equal("hc1250473063700", record.Registrant.RegistryId);
        Assert.Equal("email@qq.com", record.Registrant.Email);

        Assert.Equal(2, record.NameServers.Count);
        Assert.Equal("dns27.hichina.com", record.NameServers[0]);
        Assert.Equal("dns28.hichina.com", record.NameServers[1]);
    }
}
