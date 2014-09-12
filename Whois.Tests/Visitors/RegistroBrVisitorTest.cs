using System;
using NUnit.Framework;
using Whois.Domain;

namespace Whois.Visitors
{
    [TestFixture]
    public class RegistroBrVisitorTest
    {
        private RegistroBrVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new RegistroBrVisitor();
        }


        [Test]
        public void TestParseDateCreated()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeUolResponse);

            record = visitor.Visit(record);

            Assert.IsTrue(record.Created.HasValue);
            Assert.AreEqual(record.Created.Value, new DateTime(1996, 04, 24));
        }

        [Test]
        public void TestParseDateCreatedWhenNotRegistroBrResult()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeGoogleResponse3);

            record = visitor.Visit(record);

            Assert.IsFalse(record.Created.HasValue);
        }
    }
}
