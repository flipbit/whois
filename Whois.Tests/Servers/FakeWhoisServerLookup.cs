using System.Text;

namespace Whois.Servers
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisServerLookup : IWhoisServerLookup
    {
        public Encoding CurrentEncoding { get; private set; }

        public IWhoisServer Lookup(string domain)
        {
            return new WhoisServer("com", "test.whois.com");
        }
    }
}
