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
            var result = lookup.Lookup(new WhoisRequest("com"));

            Assert.AreEqual("whois.verisign-grs.com", result.Registrar.WhoisServer);
        }
 
        [Test]
        public void TestLookupComBr()
        {
            var result = lookup.Lookup(new WhoisRequest("br"));

            Assert.AreEqual("whois.registro.br", result.Registrar.WhoisServer);
        }
    }
}
