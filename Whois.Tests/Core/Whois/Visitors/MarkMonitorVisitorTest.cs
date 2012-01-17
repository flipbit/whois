using System;
using Flipbit.Core.Whois.Domain;
using NUnit.Framework;

namespace Flipbit.Core.Whois.Visitors
{
    [TestFixture]
    public class MarkMonitorVisitorTest
    {
        private MarkMonitorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new MarkMonitorVisitor();
        }

        [Test]
        public void TestParseDateCreated()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeGoogleResponse3);

            record = visitor.Visit(record);

            Assert.IsTrue(record.Created.HasValue);
            Assert.AreEqual(record.Created.Value, new DateTime(1997, 9, 15));
        }

        [Test]
        public void TestParseDateCreatedWhenNotMarkMonitorResult()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeCogworksResponse);

            record = visitor.Visit(record);

            Assert.IsFalse(record.Created.HasValue);
        }
    }
}
