using System;
using System.IO;
using NUnit.Framework;

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
        public void TestIsARedirectWhenTrue()
        {
            var record = new WhoisRecord(File.ReadAllText(@"..\..\Samples\Domains\sphinn.com.txt"));
            WhoisRedirect redirect;

            var result = visitor.IsARedirectRecord(record, out redirect);

            Assert.IsTrue(result);
            Assert.IsNotNull(redirect);
            Assert.AreEqual(new DateTime(2007, 4, 25), redirect.CreatedDate);
            Assert.AreEqual("sphinn.com", redirect.Domain);
            Assert.AreEqual(new DateTime(2015, 4, 25), redirect.ExpirationDate);
            Assert.AreEqual(new DateTime(2014, 4, 25), redirect.ModifiedDate);
            Assert.AreEqual("NS1.TIGERTECH.NET", redirect.Nameservers[0]);
            Assert.AreEqual("NS2.TIGERTECH.BIZ", redirect.Nameservers[1]);
            Assert.AreEqual("NS3.TIGERTECH.ORG", redirect.Nameservers[2]);
            Assert.AreEqual("http://www.tigertech.net", redirect.ReferralUrl);
            Assert.AreEqual("TIGER TECHNOLOGIES LLC", redirect.Registrar);
            Assert.AreEqual("whois.tigertech.net", redirect.Url);
        }
    }
}
