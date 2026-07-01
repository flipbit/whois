using NUnit.Framework;

namespace Whois
{
    [TestFixture]
    public class ResourceReaderTests
    {
        private ResourceReader reader;

        [SetUp]
        public void SetUp()
        {
            reader = new ResourceReader();
        }

        [Test]
        public void TestGetNames()
        {
            var names = reader.GetNames("capetown-whois.registry.net.za", "capetown");

            Assert.AreEqual(2, names.Count);
            Assert.AreEqual("Whois.Resources.capetown_whois.registry.net.za.capetown.Found.txt", names[0]);
            Assert.AreEqual("Whois.Resources.capetown_whois.registry.net.za.capetown.NotFound.txt", names[1]);
        }

        [Test]
        public void TestGetNamesWithDifferentCase()
        {
            var names = reader.GetNames("Capetown-whois.registry.net.za", "Capetown");

            Assert.AreEqual(2, names.Count);
            Assert.AreEqual("Whois.Resources.capetown_whois.registry.net.za.capetown.Found.txt", names[0]);
            Assert.AreEqual("Whois.Resources.capetown_whois.registry.net.za.capetown.NotFound.txt", names[1]);
        }

        [Test]
        public void TestGetNamesWhenNotFound()
        {
            var names = reader.GetNames("missing.server", "missing.tld");

            Assert.AreEqual(0, names.Count);
        }

        [Test]
        public void TestGetNamesWhenEmptyInputs()
        {
            var names = reader.GetNames(string.Empty, string.Empty);

            Assert.AreEqual(0, names.Count);
        }

        [Test]
        public void TestGetNamesWhenNullInputs()
        {
            var names = reader.GetNames(null, null);

            Assert.AreEqual(0, names.Count);
        }

        [Test]
        public void TestGetContent()
        {
            var content = reader.GetContent("Whois.Resources.capetown_whois.registry.net.za.capetown.Found.txt");

            Assert.IsTrue(content.Length > 0);
        }

        [Test]
        public void TestGetContentWhenNotFound()
        {
            var content = reader.GetContent("missing");

            Assert.IsTrue(content.Length == 0);
        }
    }
}
