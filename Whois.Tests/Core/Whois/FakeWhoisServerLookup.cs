using System.Text;
using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois
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
