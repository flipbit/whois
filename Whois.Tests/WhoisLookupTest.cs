using System;
using System.Text;
using System.Threading.Tasks;
using Moq;
using NUnit.Framework;
using Whois.Models;
using Whois.Net;
using Whois.Servers;

namespace Whois
{
    [TestFixture]
    public class WhoisLookupTest
    {
        private WhoisLookup lookup;

        private Mock<IWhoisServerLookup> whoisServerLookup;
        private Mock<ITcpReader> tcpReader;
        private SampleReader sampleReader;

        [SetUp]
        public void SetUp()
        {
            whoisServerLookup = new Mock<IWhoisServerLookup>();
            tcpReader = new Mock<ITcpReader>();
            sampleReader = new SampleReader();

            lookup = new WhoisLookup
            {
                TcpReader = tcpReader.Object, 
                ServerLookup = whoisServerLookup.Object
            };
        }

        [Test]
        public async Task TestLookupDomain()
        {
            var request = new WhoisRequest("google.com");

            var rootServer = new WhoisResponse
            {
                DomainName = "com",
                Registrar = new Registrar { WhoisServerUrl = "whois.markmonitor.com" }
            };

            whoisServerLookup
                .Setup(call => call.LookupAsync(request))
                .Returns(Task.FromResult(rootServer));

            tcpReader
                .Setup(call => call.Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10))
                .Returns(Task.FromResult(sampleReader.Read("whois.markmonitor.com", "com", "found.txt")));

            var result = await lookup.LookupAsync(request);

            Assert.AreEqual("google.com", result.DomainName);
            Assert.AreEqual(WhoisStatus.Found, result.Status);
        }

        [Test]
        public async Task TestLookupDomainWithIntermediateServer()
        {
            var request = new WhoisRequest("google.com");
            var intermediateResult = sampleReader.Read("whois.verisign-grs.com", "com", "found_status_registered.txt");
            var authoritativeResult = sampleReader.Read("whois.markmonitor.com", "com", "found.txt");

            var rootServer = new WhoisResponse
            {
                DomainName = "com",
                Registrar = new Registrar { WhoisServerUrl = "whois.verisign-grs.com" }
            };

            whoisServerLookup
                .Setup(call => call.LookupAsync(request))
                .Returns(Task.FromResult(rootServer));

            tcpReader
                .Setup(call => call.Read("whois.verisign-grs.com", 43, "google.com", Encoding.UTF8, 10))
                .Returns(Task.FromResult(intermediateResult));

            tcpReader
                .Setup(call => call.Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10))
                .Returns(Task.FromResult(authoritativeResult));

            var result = await lookup.LookupAsync(request);

            Assert.AreEqual("google.com", result.DomainName);
            Assert.AreEqual(WhoisStatus.Found, result.Status);

            Assert.AreEqual(authoritativeResult, result.Content);
            Assert.AreEqual(intermediateResult, result.Referrer.Content);
            Assert.AreEqual(rootServer, result.Referrer.Referrer);
        }

        [Test]
        public async Task TestLookupDomainDontFollowReferrer()
        {
            var request = new WhoisRequest { Query = "google.com", FollowReferrer = false };
            var intermediateResult = sampleReader.Read("whois.verisign-grs.com", "com", "found_status_registered.txt");

            var rootServer = new WhoisResponse
            {
                DomainName = "com",
                Registrar = new Registrar { WhoisServerUrl = "whois.verisign-grs.com" }
            };

            whoisServerLookup
                .Setup(call => call.LookupAsync(request))
                .Returns(Task.FromResult(rootServer));

            tcpReader
                .Setup(call => call.Read("whois.verisign-grs.com", 43, "google.com", Encoding.UTF8, 10))
                .Returns(Task.FromResult(intermediateResult));

            var result = await lookup.LookupAsync(request);

            Assert.AreEqual("google.com", result.DomainName);
            Assert.AreEqual(WhoisStatus.Found, result.Status);

            Assert.AreEqual(intermediateResult, result.Content);
            Assert.AreEqual(rootServer, result.Referrer);
        }

        [Test]
        public async Task TestLookupDomainSpecifyRootServer()
        {
            var request = new WhoisRequest { Query = "google.com", WhoisServerUrl = "whois.markmonitor.com" };
            var authoritativeResult = sampleReader.Read("whois.markmonitor.com", "com", "found.txt");

            tcpReader
                .Setup(call => call.Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10))
                .Returns(Task.FromResult(authoritativeResult));

            var result = await lookup.LookupAsync(request);

            Assert.AreEqual("google.com", result.DomainName);
            Assert.AreEqual(WhoisStatus.Found, result.Status);

            Assert.AreEqual(authoritativeResult, result.Content);
            Assert.AreEqual("whois.markmonitor.com", result.Referrer.WhoisServerUrl);

            whoisServerLookup
                .Verify(call => call.LookupAsync(request), Times.Never());
        }

        [Test]
        public async Task TestLookupTld()
        {
            var request = new WhoisRequest(".com");

            var rootServer = new WhoisResponse
            {
                DomainName = "com",
                Registrar = new Registrar { WhoisServerUrl = "whois.markmonitor.com" }
            };

            whoisServerLookup
                .Setup(call => call.LookupAsync(request))
                .Returns(Task.FromResult(rootServer));

            var result = await lookup.LookupAsync(request);

            Assert.AreEqual(rootServer, result);
        }

        [Test]
        public void TestLookupDomainWithEmptyQuery()
        {
            Assert.Throws<ArgumentNullException>(() => lookup.Lookup(string.Empty));
        }

        [Test]
        public void TestLookupDomainWithNullQuery()
        {
            Assert.Throws<ArgumentNullException>(() => lookup.Lookup(null, Encoding.UTF8));
        }
    }
}
