using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cnnic.Cn.Cn
{
    [TestFixture]
    public class CnParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cnnic.cn", "cn", "found.txt");
            var response = parser.Parse("whois.cnnic.cn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cnnic.cn/cn/Found", response.TemplateName);

            Assert.AreEqual("concordecals.com.cn", response.DomainName.ToString());
            Assert.AreEqual("20021209s10011s00041927-cn", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("北京新网互联科技有限公司", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2002, 3, 6, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2013, 3, 6, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("朴泰恩", response.Registrant.Name);
            Assert.AreEqual("康科陶艺制造（深圳）有限公司", response.Registrant.Organization);

             // AdminContact Details
            Assert.AreEqual("taien@concordecals.com.cn", response.AdminContact.Email);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.dns.com.cn", response.NameServers[0]);
            Assert.AreEqual("ns2.dns.com.cn", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(12, response.FieldsParsed);  
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.cnnic.cn", "cn", "reserved.txt");
            var response = parser.Parse("whois.cnnic.cn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cnnic.cn/cn/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cnnic.cn", "cn", "not_found.txt");
            var response = parser.Parse("whois.cnnic.cn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cnnic.cn/cn/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cnnic.cn", "cn", "found_status_registered.txt");
            var response = parser.Parse("whois.cnnic.cn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cnnic.cn/cn/Found", response.TemplateName);

            Assert.AreEqual("google.cn", response.DomainName.ToString());
            Assert.AreEqual("20030311s10001s00033735-cn", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2003, 3, 17, 12, 20, 5), response.Registered);
            Assert.AreEqual(new DateTime(2017, 3, 17, 12, 48, 36), response.Expiration);

             // Registrant Details
            Assert.AreEqual("cnnic-zdmd-022", response.Registrant.RegistryId);
            Assert.AreEqual("Google Ireland Holdings", response.Registrant.Name);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(6, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.AreEqual("serverUpdateProhibited", response.DomainStatus[3]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[4]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[5]);

            Assert.AreEqual(19, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved_status_reserved()
        {
            var sample = SampleReader.Read("whois.cnnic.cn", "cn", "reserved_status_reserved.txt");
            var response = parser.Parse("whois.cnnic.cn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cnnic.cn/cn/Prohibited", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_025bbs_cn()
        {
            var sample = SampleReader.Read("whois.cnnic.cn", "cn", "025bbs.cn.txt");

            var record = parser.Parse("whois.cnnic.cn", sample);

            Assert.AreEqual("20180313s10001s99456578-cn", record.RegistryDomainId);
            Assert.AreEqual("阿里云计算有限公司（万网）", record.Registrar.Name);
            Assert.AreEqual(new DateTime(2018, 3, 13, 21, 45, 16), record.Registered.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(2021, 3, 13, 21, 45, 16), record.Expiration.Value.ToUniversalTime());
            Assert.AreEqual("南京越之彬网络科技有限公司", record.Registrant.Name);
            Assert.AreEqual("hc1250473063700", record.Registrant.RegistryId);
            Assert.AreEqual("email@qq.com", record.Registrant.Email);

            Assert.AreEqual(2, record.NameServers.Count);
            Assert.AreEqual("dns27.hichina.com", record.NameServers[0]);
            Assert.AreEqual("dns28.hichina.com", record.NameServers[1]);
        }
    }
}
