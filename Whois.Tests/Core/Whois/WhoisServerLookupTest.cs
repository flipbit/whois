using System;
using NUnit.Framework;

namespace Flipbit.Core.Whois
{
    [TestFixture]
    public class WhoisServerLookupTest
    {
        private WhoisServerLookup lookup;

        [SetUp]
        public void SetUp()
        {
            lookup = new WhoisServerLookup();
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

        [Test]
        public void TestGetNameServerForComDomain()
        {
            var server = lookup.Lookup("exmaple.com");

            Assert.AreEqual("whois.verisign-grs.com", server);
        }

        [Test]
        public void TestGetNameServerForUkDomain()
        {
            var server = lookup.Lookup("exmaple.co.uk");

            Assert.AreEqual("lb-dac.nominet.org.uk", server);
        }

        [Test]
        public void TestGetNameServerForDeDomain()
        {
            var server = lookup.Lookup("exmaple.de");

            Assert.AreEqual("whois.denic.de", server);
        }

        [Test]
        public void TestGetNameServerForTkDomain()
        {
            var server = lookup.Lookup("exmaple.tk");

            Assert.AreEqual("whois.dot.tk", server);
        }

        [Test]
        public void TestGetNameServerForPtDomain()
        {
            var server = lookup.Lookup("example.pt");

            Assert.AreEqual("whois.dns.pt", server);
        }

        [Test]
        public void TestGetNameServerForInvalidDomain()
        {
            try
            {
                lookup.Lookup("exmaple.invalid!");

                Assert.Fail("Should of thrown an exception!");
            }
            catch (ApplicationException)
            {                
            }
            catch (Exception)
            {
                Assert.Fail("Unexpected exception thrown!");
            }
        }
    }
}
