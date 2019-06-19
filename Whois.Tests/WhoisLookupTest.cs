using NUnit.Framework;

namespace Whois
{
    /// <summary>
    /// These tests just test that the Visitor Pattern is functioning correctly, the specific
    /// WHOIS tests are contained in the "Vistors" folder.
    /// </summary>
    [TestFixture]
    public class WhoisLookupTest
    {
        private WhoisLookup lookup;

        [SetUp]
        public void SetUp()
        {
            lookup = new WhoisLookup();
        }
    }
}
