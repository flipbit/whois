using System.Text;
using Whois.Interfaces;

namespace Whois
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisServerLookup : IWhoisServerLookup
    {
        public Encoding CurrentEncoding { get; private set; }

        public string Lookup(string domain)
        {
            return "test.whois.com";
        }
    }
}
