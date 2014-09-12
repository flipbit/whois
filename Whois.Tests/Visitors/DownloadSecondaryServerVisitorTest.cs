using NUnit.Framework;
using Whois.Arrays;
using Whois.Domain;

namespace Whois.Visitors
{
    [TestFixture]
    public class DownloadSecondaryServerVisitorTest
    {
        private DownloadSecondaryServerVisitor vistior;

        [SetUp]
        public void SetUp()
        {
            // Initialize visitor with the Fake TcpReader Factory so we get canned responses
            vistior = new DownloadSecondaryServerVisitor { TcpReaderFactory = new FakeTcpReaderFactory() };
        }

        [Test]
        public void TestDownloadSecondaryServerVisitor()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeGoogleResponse2);
            record.Domain = "google.com";

            record = vistior.Visit(record);

            // Should of downloaded the MarkMonitor response (response 3)
            Assert.Greater(record.Text.IndexOfLineContaining("MarkMonitor"), -1);
        }
    }
}
