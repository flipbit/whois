using NUnit.Framework;
using Whois.Visitors;

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

            lookup.Visitors.Clear();
        }

        [Test]
        public void TestLookupWithOneVisitor()
        {
            lookup.Visitors.Add(new FakeWhoisVisitor("first"));

            var result = lookup.Lookup("example.com");

            Assert.AreEqual("first\r\n", result.ToString());
        }

        [Test]
        public void TestLookupWithTwoVisitors()
        {
            lookup.Visitors.Add(new FakeWhoisVisitor("first"));
            lookup.Visitors.Add(new FakeWhoisVisitor("second"));

            var result = lookup.Lookup("example.com");

            Assert.AreEqual("second\r\n", result.ToString());
        }
    }
}
