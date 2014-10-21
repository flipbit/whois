using System;
using NUnit.Framework;
using Whois.Domain;
using Whois.Net;

namespace Whois.Visitors
{
    [TestFixture]
    public class NominetVisitorTest
    {
        private NominetVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new NominetVisitor();
        }


        [Test]
        public void TestParseDateCreated()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeCogworksResponse);

            record = visitor.Visit(record);

            Assert.IsTrue(record.Created.HasValue);
            Assert.AreEqual(record.Created.Value, new DateTime(2003, 8, 26));
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
