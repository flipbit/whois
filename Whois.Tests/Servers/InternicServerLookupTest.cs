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
        public void TestGetTldForNullInput()
        {
            var tld = lookup.GetTld(null);

            Assert.AreEqual(string.Empty, tld);
        }

        [Test]
        public void TestGetTldForInvalidInput()
        {
            var tld = lookup.GetTld("invalid domain name");

            Assert.AreEqual(string.Empty, tld);
        }

        [Test]
        public void TestGetTldCountrySpecificDomain()
        {
            var tld = lookup.GetTld("example.co.uk");

            Assert.AreEqual("uk", tld);
        }

        [Test]
        public void TestGetTldInternationalDomain()
        {
            var tld = lookup.GetTld("example.com");

            Assert.AreEqual("com", tld);
        }
    }
}
