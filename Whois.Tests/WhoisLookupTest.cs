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

            lookup = new WhoisLookup();

            lookup.TcpReader = tcpReader.Object;
            lookup.ServerLookup = whoisServerLookup.Object;
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
