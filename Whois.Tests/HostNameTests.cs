using System;
using NUnit.Framework;

namespace Whois
{
    [TestFixture]
    public class HostNameTests
    {
        [Test]
        public void TestCreateValidHostName()
        {
            var host = new HostName("flipbit.co.uk");

            Assert.AreEqual("flipbit.co.uk", host.ToString());
            Assert.AreEqual(false, host.IsPunyCode);
            Assert.AreEqual(false, host.IsTld);
            Assert.AreEqual("uk", host.Tld);
        }

        [Test]
        public void TestCreateValidHostNameWhenTld()
        {
            var host = new HostName("uk");

            Assert.AreEqual("uk", host.ToString());
            Assert.AreEqual(false, host.IsPunyCode);
            Assert.AreEqual(true, host.IsTld);
            Assert.AreEqual("uk", host.Tld);
        }

        [Test]
        public void TestCreateValidHostNameWhendInvalid()
        {
            Assert.Throws<FormatException>(() => new HostName("hello world"));
        }

        [Test]
        public void TestCreateValidHostNameWhendNull()
        {
            Assert.Throws<ArgumentNullException>(() => new HostName(null));
        }

        [Test]
        public void TestCreateValidHostNameWhenPunyCode()
        {
            var host = new HostName("nic.xn--vermgensberater-ctb");

            Assert.AreEqual("nic.xn--vermgensberater-ctb", host.ToString());
            Assert.AreEqual(true, host.IsPunyCode);
            Assert.AreEqual(false, host.IsTld);
            Assert.AreEqual("xn--vermgensberater-ctb", host.Tld);
            Assert.AreEqual("nic.vermögensberater", host.ToUnicodeString());
        }

        [Test]
        public void TestCreateValidHostNameWhenUnicode()
        {
            var host = new HostName("nic.vermögensberater");

            Assert.AreEqual("nic.xn--vermgensberater-ctb", host.ToString());
            Assert.AreEqual(true, host.IsPunyCode);
            Assert.AreEqual(false, host.IsTld);
            Assert.AreEqual("xn--vermgensberater-ctb", host.Tld);
            Assert.AreEqual("nic.vermögensberater", host.ToUnicodeString());
        }

        [Test]
        public void TestCreateValidHostNameWhenHasMultipleSubdomains()
        {
            var host = new HostName("www.housekenya.co.ke");

            Assert.AreEqual("www.housekenya.co.ke", host.ToString());
            Assert.AreEqual(false, host.IsPunyCode);
            Assert.AreEqual(false, host.IsTld);
            Assert.AreEqual("ke", host.Tld);
            Assert.AreEqual("www.housekenya.co.ke", host.ToUnicodeString());
        }
    }
}
