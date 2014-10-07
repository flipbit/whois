using NUnit.Framework;

namespace Whois
{
    [TestFixture]
    public class EmbeddedPatternReaderTest
    {
        private EmbeddedPatternReader reader;

        [SetUp]
        public void SetUp()
        {
            reader = new EmbeddedPatternReader();
        }

        [Test]
        public void TestListAllPatternsInAssembly()
        {
            var patterns = reader.GetResourceNames(GetType().Assembly, "Whois.Patterns");

            Assert.AreEqual(2, patterns.Count);
            Assert.AreEqual("Whois.Patterns.TestPatternOne.txt", patterns[0]);
            Assert.AreEqual("Whois.Patterns.TestPatternTwo.txt", patterns[1]);
        }

        [Test]
        public void TestListAllWhoisPatterns()
        {
            var patterns = reader.GetResourceNames();

            Assert.Less(0, patterns.Count);
        }

        [Test]
        public void TestReadEmbeddedResource()
        {
            var result = reader.Read(GetType().Assembly, "Whois.Patterns.TestPatternOne.txt");

            Assert.AreEqual("Test Pattern One", result);
        }

        [Test]
        public void TestReadEmbeddedResources()
        {
            var result = reader.ReadNamespace(GetType().Assembly, "Whois.Patterns");

            Assert.AreEqual(2, result.Count);
            Assert.AreEqual("Test Pattern One", result[0]);
            Assert.AreEqual("Test Pattern Two", result[1]);
        }
    }
}
