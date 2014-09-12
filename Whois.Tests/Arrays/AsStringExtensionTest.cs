using System.Collections;
using NUnit.Framework;

namespace Whois.Arrays
{
    [TestFixture]
    public class AsStringExtensionTest
    {
        [Test]
        public void TestEmptyListAsString()
        {
            var array = new ArrayList();

            Assert.AreEqual(string.Empty, array.AsString());
        }

        [Test]
        public void TestNonEmptyListAsString()
        {
            var array = new ArrayList { "First", "Second", "Third" };

            Assert.AreEqual("First\r\nSecond\r\nThird\r\n", array.AsString());
        }
    }
}
