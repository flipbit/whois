using System;
using System.Threading.Tasks;
using Moq;
using NUnit.Framework;
using Whois.Models;
using Whois.Servers;

namespace Whois.Visitors
{
    [TestFixture]
    public class WhoisServerVisitorTest
    {
        private WhoisServerVisitor visitor;
        private Mock<IWhoisServerLookup> lookup;

        [SetUp]
        public void SetUp()
        {
            lookup = new Mock<IWhoisServerLookup>();

            visitor = new WhoisServerVisitor
            {
                WhoisServerLookup = lookup.Object
            };
        }

        [Test]
        public async Task TestLookupWhoisServer()
        {
            lookup
                .Setup(call => call.LookupAsync("com"))
                .ReturnsAsync(new WhoisServer("com", "test.whois.com"));

            var state = new LookupState { Tld = "com" };

            Assert.IsNull(state.WhoisServer);

            state = await visitor.Visit(state);

            Assert.AreEqual("test.whois.com", state.WhoisServer.Url);

            var cached = visitor.Cache.Get("com");

            Assert.AreEqual("test.whois.com", cached.Url);
        }

        [Test]
        public async Task TestLookupWhoisServerWhenCached()
        {
            visitor.Cache.Set(new WhoisServer("com", "test.whois.com"));

            var state = new LookupState { Tld = "com" };

            Assert.IsNull(state.WhoisServer);

            state = await visitor.Visit(state);

            Assert.AreEqual("test.whois.com", state.WhoisServer.Url);
        }

        [Test]
        public void TestLookupWhoisServerWhenNotFound()
        {
            var state = new LookupState { Tld = "com" };

            Assert.Throws<AggregateException>(() => Task.Run(async () => await visitor.Visit(state)).Wait());
        }
    }
}
