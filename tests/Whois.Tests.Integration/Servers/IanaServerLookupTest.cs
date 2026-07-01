using Xunit;
using Whois.Servers;

namespace Whois
{
    public class IanaServerLookupTest
    {
        private readonly IanaServerLookup lookup;

        public IanaServerLookupTest()
        {
            lookup = new IanaServerLookup();
        }

        [Fact]
        public void TestLookupCom()
        {
            var result = lookup.Lookup(new WhoisRequest("com"));

            Assert.Equal("whois.verisign-grs.com", result.Registrar.WhoisServer.ToString());
        }

        [Fact]
        public void TestLookupComBr()
        {
            var result = lookup.Lookup(new WhoisRequest("br"));

            Assert.Equal("whois.registro.br", result.Registrar.WhoisServer.ToString());
        }
    }
}
