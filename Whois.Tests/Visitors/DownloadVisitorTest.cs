using NUnit.Framework;
using Whois.Net;
using Whois.Servers;

namespace Whois.Visitors
{
    [TestFixture]
    public class DownloadVisitorTest
    {
        private DownloadVisitor visitor;
        private FakeTcpReaderFactory factory;

        [SetUp]
        public void SetUp()
        {
            // Initialize visitor with the Fake TcpReader Factory so we get canned responses
            factory = new FakeTcpReaderFactory();
            visitor = new DownloadVisitor { TcpReaderFactory = factory };
        }

        [Test]
        public void TestDownloadWhoisResults()
        {
            var record = new WhoisRecord { Domain = "flipbit.co.uk", Server = new WhoisServer("uk", "whois.com") };

            factory.Reader = new FakeTcpReader("WHOIS Data");

            visitor.Visit(record);

            Assert.AreEqual("WHOIS Data", record.Text);
        }
    }
}
