using NUnit.Framework;
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
            lookup = new IanaServerLookup();
        }

        [Test]
        public void TestLookupCom()
        {
            var result = lookup.Lookup("com");

            Assert.AreEqual("whois.verisign-grs.com", result.ParsedWhoisServer.Url);
        }
    }
}
