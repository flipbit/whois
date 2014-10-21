using System;
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
        public void TestGetNameServerForComDomain()
        {
            var server = lookup.Lookup("exmaple.com");

            Assert.AreEqual("whois.verisign-grs.com", server.Url);
        }

        [Test]
        public void TestGetNameServerForUkDomain()
        {
            var server = lookup.Lookup("exmaple.co.uk");

            Assert.AreEqual("whois.nic.uk", server.Url);
        }

        [Test]
        public void TestGetNameServerForDeDomain()
        {
            var server = lookup.Lookup("exmaple.de");

            Assert.AreEqual("whois.denic.de", server.Url);
        }

        [Test]
        public void TestGetNameServerForTkDomain()
        {
            var server = lookup.Lookup("exmaple.tk");

            Assert.AreEqual("whois.dot.tk", server.Url);
        }

        [Test]
        public void TestGetNameServerForPtDomain()
        {
            var server = lookup.Lookup("example.pt");

            Assert.AreEqual("whois.dns.pt", server.Url);
        }

        [Test]
        public void TestGetNameServerForBrDomain()
        {
            var server = lookup.Lookup("example.com.br");

            Assert.AreEqual("registro.br", server.Url);
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
