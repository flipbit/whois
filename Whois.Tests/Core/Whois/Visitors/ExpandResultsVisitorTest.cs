using Flipbit.Core.Whois.Arrays;
using Flipbit.Core.Whois.Domain;
using NUnit.Framework;

namespace Flipbit.Core.Whois.Visitors
{
    [TestFixture]
    public class ExpandResultsVisitorTest
    {
        private ExpandResultsVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new ExpandResultsVisitor { TcpReaderFactory = new FakeTcpReaderFactory() };
        }

        [Test]
        public void TestExpandResultsWhenResultsIncludeMagicString()
        {
            // Initial the record with the canned response of un-expanded results.
            var record = new WhoisRecord(FakeTcpReader.FakeGoogleResponse1);
            record.Domain = "google.com";

            // confirm there are no WHOIS server domains in the results.
            Assert.AreEqual(record.Text.IndexOfLineContaining("Whois Server:"), -1);

            record = visitor.Visit(record);

            // confirm the results now have whois server domains.
            Assert.Greater(record.Text.IndexOfLineContaining("Whois Server:"), -1);
        }

        [Test]
        public void TestExpandResultsWhenResultsDoesntIncludeMagicString()
        {
            // Initial the record with the canned response of un-expanded results.
            var record = new WhoisRecord(FakeTcpReader.FakeCogworksResponse);
            record.Domain = "cogworks.co.uk";

            record = visitor.Visit(record);

            // confirm the results have not changed
            Assert.Greater(record.Text.IndexOfLineContaining("Nominet"), -1);
        }


    }
}
