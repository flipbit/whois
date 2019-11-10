using NUnit.Framework;

namespace Whois.Servers
{
    [TestFixture]
    public class WhoisServerCacheTests
    {
        private WhoisServerCache cache;

        [SetUp]
        public void SetUp()
        {
            cache = new WhoisServerCache();
        }

        [Test]
        public void TestGetServerWhenNotCached()
        {
            var server = cache.Get("com");

            Assert.IsNull(server);
        }

        [Test]
        public void TestGetServerWhenCached()
        {
            var existing = new WhoisResponse { DomainName = new HostName("com") };
            cache.Set(existing);

            var server = cache.Get("com");

            Assert.AreEqual(existing, server);
        }

        [Test]
        public void TestCacheUpdate()
        {
            var first = new WhoisResponse { DomainName = new HostName("com")};
            cache.Set(first);
            var second = new WhoisResponse { DomainName = new HostName("com") };
            cache.Set(second);

            var server = cache.Get("com");

            Assert.AreEqual(second, server);
        }
    }
}
