using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using Whois.Models;

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
            var existing = new WhoisServer("com", "server.com");
            cache.Set(existing);

            var server = cache.Get("com");

            Assert.AreEqual(existing, server);
        }

        [Test]
        public void TestCacheUpdate()
        {
            var first = new WhoisServer("com", "second.com");
            cache.Set(first);
            var second = new WhoisServer("com", "second.com");
            cache.Set(second);

            var server = cache.Get("com");

            Assert.AreEqual(second, server);
        }
    }
}
