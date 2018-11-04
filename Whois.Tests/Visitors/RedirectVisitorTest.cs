using System;
using System.IO;
using System.Threading.Tasks;
using NUnit.Framework;
using Whois.Models;
using Whois.Net;

namespace Whois.Visitors
{
    [TestFixture]
    public class RedirectVisitorTest
    {
        private RedirectVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new RedirectVisitor();
        }

        [Test]
        public async Task TestRedirectedWhoisData()
        {
            TcpReaderFactory.Bind(() => new FakeTcpReader("Redirected WHOIS Data"));

            var record = new WhoisResponse(File.ReadAllText(@"..\..\..\Samples\Redirects\MarkMonitor.txt"));
            var state = new LookupState
            {
                Response = record,
                Options = WhoisOptions.Defaults,
                Domain = "example.com" 
            };

            var result = await visitor.Visit(state);

            Assert.AreEqual("Redirected WHOIS Data", result.Response.Content);
        }

        [Test]
        public async Task TestNonRedirectedWhoisData()
        {
            TcpReaderFactory.Bind(() => new FakeTcpReader("Redirected WHOIS Data"));

            var response = File.ReadAllText(@"..\..\..\Samples\Domains\google.co.uk.txt");
            var record = new WhoisResponse(response);
            var state = new LookupState
            {
                Response = record,
                Options = WhoisOptions.Defaults,
                Domain = "example.com" 
            };

            var result = await visitor.Visit(state);

            Assert.AreEqual(response, result.Response.Content);
        }
    }
}
