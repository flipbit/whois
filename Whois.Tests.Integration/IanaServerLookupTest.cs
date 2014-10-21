using NUnit.Framework;
using Whois.Net;
using Whois.Servers;

namespace Whois
{
    [TestFixture]
    public class IanaServerLookupTest
    {
        private IanaServerLookup lookup;

        [SetUp]
        public void SetUp()
        {
            lookup = new IanaServerLookup { TcpReaderFactory = new TcpReaderFactory() };
        }

        [Test]
        public void TestLookupCom()
        {
            var result = lookup.Lookup("google.be");

            Assert.AreEqual("", result);
        }
    }
}
