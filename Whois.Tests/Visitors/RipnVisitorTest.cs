using System;
using NUnit.Framework;
using Whois.Domain;
using Whois.Net;

namespace Whois.Visitors
{
    [TestFixture]
    public class RipnVisitorTest
    {
        private RipnVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new RipnVisitor();
        }


        [Test]
        public void TestParseDateCreated()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeYaRuResponse);

            record = visitor.Visit(record);

            Assert.IsTrue(record.Created.HasValue);
            Assert.AreEqual(record.Created.Value, new DateTime(1999, 7, 12));
        }

        [Test]
        public void TestParseDateCreatedWhenNotNominetResult()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeGoogleResponse3);

            record = visitor.Visit(record);

            Assert.IsFalse(record.Created.HasValue);
        }
    }
}
