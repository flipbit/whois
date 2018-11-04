using System.Threading.Tasks;
using NUnit.Framework;

namespace Whois.Visitors
{
    [TestFixture]
    public class ValidateVisitorTest
    {
        private ValidateVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new ValidateVisitor();
        }

        [Test]
        public async Task TestValidateDomainAndTld()
        {
            var state = new LookupState { Domain = "example.com" };

            var result = await visitor.Visit(state);

            Assert.AreEqual("example.com", result.Domain);
            Assert.AreEqual("com", result.Tld);
        }

        [Test]
        public void TestValidateWhenDomainTooLong()
        {
            var state = new LookupState { Domain = "example-too-long-domain-name-1234456678990123445678901233456778901234456678890.com" };

            Assert.Throws<WhoisException>(() => visitor.Visit(state));
        }

        [Test]
        public async Task TestValidateDomainAndCcTld()
        {
            var state = new LookupState { Domain = "example.co.uk" };

            var result = await visitor.Visit(state);

            Assert.AreEqual("example.co.uk", result.Domain);
            Assert.AreEqual("uk", result.Tld);
        }

        [Test]
        public async Task TestValidateDomainAndNewTld()
        {
            var state = new LookupState { Domain = "example.ninja" };

            var result = await visitor.Visit(state);

            Assert.AreEqual("example.ninja", result.Domain);
            Assert.AreEqual("ninja", result.Tld);
        }

        [Test]
        public void TestValidateWhenEmptyString()
        {
            var state = new LookupState { Domain = "" };

            Assert.Throws<WhoisException>(() => visitor.Visit(state));
        }

        [Test]
        public void TestValidateWhenNullString()
        {
            var state = new LookupState { Domain = "" };

            Assert.Throws<WhoisException>(() => visitor.Visit(state));
        }
    }
}
