using Xunit;

namespace Whois.Servers
{
    public class WhoisServerCacheTests
    {
        private WhoisServerCache cache;

        public WhoisServerCacheTests()
        {
            cache = new WhoisServerCache();
        }

        [Fact]
        public void TestGetServerWhenNotCached()
        {
            var server = cache.Get("com");

            Assert.Null(server);
        }

        [Fact]
        public void TestGetServerWhenCached()
        {
            var existing = new WhoisResponse { DomainName = new HostName("com") };
            cache.Set(existing);

            var server = cache.Get("com");

            Assert.Equal(existing, server);
        }

        [Fact]
        public void TestCacheUpdate()
        {
            var first = new WhoisResponse { DomainName = new HostName("com")};
            cache.Set(first);
            var second = new WhoisResponse { DomainName = new HostName("com") };
            cache.Set(second);

            var server = cache.Get("com");

            Assert.Equal(second, server);
        }
    }
}
