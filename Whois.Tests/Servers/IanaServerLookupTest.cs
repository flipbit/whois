using System.IO;
using NUnit.Framework;
using Whois.Net;

namespace Whois.Servers
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
            var com = File.ReadAllText("../../Samples/Tlds/com.txt");

            var reader = new FakeTcpReader(com);

            lookup.TcpReaderFactory = new FakeTcpReaderFactory(reader);

            var result = lookup.Lookup("test.com");

            Assert.AreEqual("COM", result.TLD);
            Assert.AreEqual("whois.verisign-grs.com", result.Url);
        }

        [Test]
        public void TestLookupBe()
        {
            var com = File.ReadAllText("../../Samples/Tlds/be.txt");

            var reader = new FakeTcpReader(com);

            lookup.TcpReaderFactory = new FakeTcpReaderFactory(reader);

            var result = lookup.Lookup("test.com");

            Assert.AreEqual("BE", result.TLD);
            Assert.AreEqual("whois.dns.be", result.Url);
        }
    }
}
