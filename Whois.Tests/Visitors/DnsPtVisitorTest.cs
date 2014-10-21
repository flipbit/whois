using System;
using NUnit.Framework;
using Whois.Domain;
using Whois.Net;

namespace Whois.Visitors
{
    [TestFixture]
    public class DnsPtVisitorTest
    {
        private DnsPtVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new DnsPtVisitor();
        }


        [Test]
        public void TestParseDateCreated()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeSapoResponse);

            record = visitor.Visit(record);

            Assert.IsTrue(record.Created.HasValue);
            Assert.AreEqual(record.Created.Value, new DateTime(2002, 10, 30));
        }

        [Test]
        public void TestParseDateCreatedWhenNotDnsPtResult()
        {
            var record = new WhoisRecord(FakeTcpReader.FakeGoogleResponse3);

            record = visitor.Visit(record);

            Assert.IsFalse(record.Created.HasValue);
        }
    }
}
