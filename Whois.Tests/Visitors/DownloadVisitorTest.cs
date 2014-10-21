using System.Text;
using NUnit.Framework;
using Whois.Domain;
using Whois.Extensions;
using Whois.Net;

namespace Whois.Visitors
{
    [TestFixture]
    public class DownloadVisitorTest
    {
        private DownloadVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            // Initialize visitor with the Fake TcpReader Factory so we get canned responses
            visitor = new DownloadVisitor { TcpReaderFactory = new FakeTcpReaderFactory() };
        }

        [Test]
        public void TestDownloadCogworksCoUk()
        {
            var record = new WhoisRecord {Domain = "cogworks.co.uk"};

            visitor.Visit(record);

            // Should of gone to NOMINET
            Assert.Greater(record.Text.IndexOfLineContaining("Nominet"), -1);
        }

        [Test]
        public void TestDownloadGoogleCom()
        {
            var record = new WhoisRecord { Domain = "google.com" };

            visitor.Visit(record);

            // Should returned multiple matches (extra spam records)
            Assert.Greater(record.Text.IndexOfLineContaining(@"To single out one record, look it up with ""xxx"""), -1);
        }

        [Test]
        public void TestDownloadSapoPt()
        {
            var encoding = Encoding.GetEncoding("ISO-8859-1");
            visitor = new DownloadVisitor(encoding) { TcpReaderFactory = new FakeTcpReaderFactory() };

            var record = new WhoisRecord { Domain = "sapo.pt" };
            visitor.Visit(record);

            const string text = "Nome de domínio / Domain Name: sapo.pt";

            // Should have returned record in Portuguese (pt-PT)
            Assert.Greater(record.Text.IndexOfLineContaining(text), -1);
        }

        [Test]
        public void TestDownloadUolComBr()
        {
            var encoding = Encoding.GetEncoding("ISO-8859-1");
            visitor = new DownloadVisitor(encoding) { TcpReaderFactory = new FakeTcpReaderFactory() };

            var record = new WhoisRecord { Domain = "uol.com.br" };
            visitor.Visit(record);

            const string text = "cert@cert.br";

            // Should have returned record in Brazilian Portuguese (pt-BR)
            Assert.Greater(record.Text.IndexOfLineContaining(text), -1);
        }
    }
}
