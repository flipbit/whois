using NUnit.Framework;

namespace Whois.Servers
{
    [TestFixture]
    public class InternicServerLookupTest
    {
        private InternicServerLookup lookup;

        [SetUp]
        public void SetUp()
        {
            lookup = new InternicServerLookup();
        }

        [Test]
        public void TestLookupCom()
        {
            var server = lookup.Lookup("com");

            Assert.AreEqual("com", server.Tld);
            Assert.AreEqual("whois.verisign-grs.com", server.Url);
        }

        [Test]
        public void TestLookupUk()
        {
            var server = lookup.Lookup("uk");

            Assert.AreEqual("uk", server.Tld);
            Assert.AreEqual("whois.nic.uk", server.Url);
        }

        [Test]
        public void TestLookupTk()
        {
            var server = lookup.Lookup("tk");

            Assert.AreEqual("tk", server.Tld);
            Assert.AreEqual("whois.dot.tk", server.Url);
        }

        [Test]
        public void TestLookupUnknown()
        {
            var server = lookup.Lookup("unknown-tld");

            Assert.AreEqual("unknown-tld", server.Tld);
            Assert.AreEqual("whois.internic.net", server.Url);
        }

        [Test]
        public void TestLookupInvalid()
        {
            Assert.Throws<WhoisException>(() => lookup.Lookup("invalid tld"));
        }
    }
}
