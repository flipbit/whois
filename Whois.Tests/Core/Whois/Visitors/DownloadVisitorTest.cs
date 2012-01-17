using Flipbit.Core.Whois.Arrays;
using Flipbit.Core.Whois.Domain;
using NUnit.Framework;

namespace Flipbit.Core.Whois.Visitors
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
    }
}
