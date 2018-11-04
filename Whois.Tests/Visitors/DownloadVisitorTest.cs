using NUnit.Framework;
using Whois.Models;
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
            visitor = new DownloadVisitor();
        }

        [Test]
        public void TestDownloadWhoisResults()
        {
            TcpReaderFactory.Bind(() => new FakeTcpReader("WHOIS Data"));

            var server =  new WhoisServer("uk", "whois.com"); 

            var lookup = new LookupState
            {
                WhoisServer = server,
                Domain = "flipbit.co.uk",
                Options = WhoisOptions.Defaults
            };

            visitor.Visit(lookup);

            Assert.AreEqual("WHOIS Data", lookup.Response.Content);
        }
    }
}
