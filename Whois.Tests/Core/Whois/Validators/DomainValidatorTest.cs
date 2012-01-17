using NUnit.Framework;

namespace Flipbit.Core.Whois.Validators
{
    [TestFixture]
    public class DomainValidatorTest
    {
        [Test]
        public void TestEmptyString()
        {
            var result = new DomainValidator().Valid(string.Empty);

            Assert.IsFalse(result);
        }

        [Test]
        public void TestInvalidString()
        {
            var result = new DomainValidator().Valid("not a domain name");

            Assert.IsFalse(result);
        }

        [Test]
        public void TestValidUkString()
        {
            var result = new DomainValidator().Valid("cogworks.co.uk");

            Assert.IsTrue(result);
        }

        [Test]
        public void TestValidComString()
        {
            var result = new DomainValidator().Valid("example.com");

            Assert.IsTrue(result);
        }

        [Test]
        public void TestValidMuseumString()
        {
            var result = new DomainValidator().Valid("example.museum");

            Assert.IsTrue(result);
        }
    }
}
