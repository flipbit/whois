using System;
using System.Text;
using System.Threading.Tasks;
using NSubstitute;
using Whois.Net;
using Whois.Servers;
using Xunit;

namespace Whois
{
    public class WhoisLookupTest
    {
        private WhoisLookup lookup;

        private IWhoisServerLookup whoisServerLookup;
        private ITcpReader tcpReader;
        private SampleReader sampleReader;

        public WhoisLookupTest()
        {
            whoisServerLookup = Substitute.For<IWhoisServerLookup>();
            tcpReader = Substitute.For<ITcpReader>();
            sampleReader = new SampleReader();

            lookup = new WhoisLookup
            {
                TcpReader = tcpReader,
                ServerLookup = whoisServerLookup
            };
        }

        [Fact]
        public async Task TestLookupDomain()
        {
            var request = new WhoisRequest("google.com");

            var rootServer = new WhoisResponse
            {
                DomainName = new HostName("com"),
                Registrar = new Registrar { WhoisServer = new HostName("whois.markmonitor.com") }
            };

            whoisServerLookup.LookupAsync(request).Returns(rootServer);

            tcpReader
                .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10)
                .Returns(sampleReader.Read("whois.markmonitor.com", "com", "found.txt"));

            var result = await lookup.LookupAsync(request);

            Assert.Equal("google.com", result.DomainName.ToString());
            Assert.Equal(WhoisStatus.Found, result.Status);
        }

        [Fact]
        public async Task TestLookupDomainWithIntermediateServer()
        {
            var request = new WhoisRequest("google.com");
            var intermediateResult = sampleReader.Read("whois.verisign-grs.com", "com", "found_status_registered.txt");
            var authoritativeResult = sampleReader.Read("whois.markmonitor.com", "com", "found.txt");

            var rootServer = new WhoisResponse
            {
                DomainName = new HostName("com"),
                Registrar = new Registrar { WhoisServer = new HostName("whois.verisign-grs.com") }
            };

            whoisServerLookup.LookupAsync(request).Returns(rootServer);

            tcpReader
                .Read("whois.verisign-grs.com", 43, "google.com", Encoding.UTF8, 10)
                .Returns(intermediateResult);

            tcpReader
                .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10)
                .Returns(authoritativeResult);

            var result = await lookup.LookupAsync(request);

            Assert.Equal("google.com", result.DomainName.ToString());
            Assert.Equal(WhoisStatus.Found, result.Status);

            Assert.Equal(authoritativeResult, result.Content);
            Assert.Equal(intermediateResult, result.Referrer.Content);
            Assert.Equal(rootServer, result.Referrer.Referrer);
        }

        [Fact]
        public async Task TestLookupDomainDontFollowReferrer()
        {
            var request = new WhoisRequest { Query = "google.com", FollowReferrer = false };
            var intermediateResult = sampleReader.Read("whois.verisign-grs.com", "com", "found_status_registered.txt");

            var rootServer = new WhoisResponse
            {
                DomainName = new HostName("com"),
                Registrar = new Registrar { WhoisServer = new HostName("whois.verisign-grs.com") }
            };

            whoisServerLookup.LookupAsync(request).Returns(rootServer);

            tcpReader
                .Read("whois.verisign-grs.com", 43, "google.com", Encoding.UTF8, 10)
                .Returns(intermediateResult);

            var result = await lookup.LookupAsync(request);

            Assert.Equal("google.com", result.DomainName.ToString());
            Assert.Equal(WhoisStatus.Found, result.Status);

            Assert.Equal(intermediateResult, result.Content);
            Assert.Equal(rootServer, result.Referrer);
        }

        [Fact]
        public async Task TestLookupDomainSpecifyRootServer()
        {
            var request = new WhoisRequest { Query = "google.com", WhoisServer = "whois.markmonitor.com" };
            var authoritativeResult = sampleReader.Read("whois.markmonitor.com", "com", "found.txt");

            tcpReader
                .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10)
                .Returns(authoritativeResult);

            var result = await lookup.LookupAsync(request);

            Assert.Equal("google.com", result.DomainName.ToString());
            Assert.Equal(WhoisStatus.Found, result.Status);

            Assert.Equal(authoritativeResult, result.Content);
            Assert.Equal("whois.markmonitor.com", result.Referrer.WhoisServer.Value);

            await whoisServerLookup.DidNotReceive().LookupAsync(request);
        }

        [Fact]
        public async Task TestLookupTld()
        {
            var request = new WhoisRequest(".com");

            var rootServer = new WhoisResponse
            {
                DomainName = new HostName("com"),
                Registrar = new Registrar { WhoisServer = new HostName("whois.markmonitor.com") }
            };

            whoisServerLookup.LookupAsync(request).Returns(rootServer);

            var result = await lookup.LookupAsync(request);

            Assert.Equal(rootServer, result);
        }

        [Fact]
        public void TestLookupDomainWithEmptyQuery()
        {
            Assert.Throws<ArgumentNullException>(() => lookup.Lookup(string.Empty));
        }

        [Fact]
        public void TestLookupDomainWithNullQuery()
        {
            Assert.Throws<ArgumentNullException>(() => lookup.Lookup(null, Encoding.UTF8));
        }

        /// <summary>
        /// When looking up a WHOIS domain, we follow a chain of responses:
        ///
        ///   Root Server > Intermediate Server > Authoritative Server
        ///
        /// Sometimes the response at the end of the chain contains less information than an
        /// intermediate step.  In this case, we return the response with the most information
        /// </summary>
        [Fact]
        public async Task TestLookupDomainUseBestResponse()
        {
            // Setup our initial request
            var request = new WhoisRequest { Query = "fark.co", FollowReferrer = true };

            // Setup the inital root server response
            var rootServer = new WhoisResponse
            {
                DomainName = new HostName("co"),
                Registrar = new Registrar { WhoisServer = new HostName("whois.nic.co") }
            };
            whoisServerLookup.LookupAsync(request).Returns(rootServer);

            // Setup the intermediate server response
            var intermediateResult = sampleReader.Read("whois.nic.co", "co", "fark.co.txt");
            tcpReader
                .Read("whois.nic.co", 43, "fark.co", Encoding.UTF8, 10)
                .Returns(intermediateResult);

            // Setup the authoritative server response
            // Note: this contains less data than the intermediate response, so should be ignored
            var authoritativeResult = sampleReader.Read("whois.dynadot.com", "co", "fark.co.txt");
            tcpReader
                .Read("whois.dynadot.com", 43, "fark.co", Encoding.UTF8, 10)
                .Returns(authoritativeResult);

            var result = await lookup.LookupAsync(request);

            Assert.Equal("fark.co", result.DomainName.ToString());
            Assert.Equal(WhoisStatus.Found, result.Status);

            Assert.Equal(intermediateResult, result.Content);
            Assert.Equal(rootServer, result.Referrer);
        }

    }
}
