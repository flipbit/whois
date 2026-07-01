using System;
using Xunit;

namespace Whois
{
    public class HostNameTests
    {
        [Fact]
        public void TestCreateValidHostName()
        {
            var host = new HostName("flipbit.co.uk");

            Assert.Equal("flipbit.co.uk", host.ToString());
            Assert.False(host.IsPunyCode);
            Assert.False(host.IsTld);
            Assert.Equal("uk", host.Tld);
        }

        [Fact]
        public void TestCreateValidHostNameWhenTld()
        {
            var host = new HostName("uk");

            Assert.Equal("uk", host.ToString());
            Assert.False(host.IsPunyCode);
            Assert.True(host.IsTld);
            Assert.Equal("uk", host.Tld);
        }

        [Fact]
        public void TestCreateValidHostNameWhendInvalid()
        {
            Assert.Throws<FormatException>(() => new HostName("hello world"));
        }

        [Fact]
        public void TestCreateValidHostNameWhendNull()
        {
            Assert.Throws<ArgumentNullException>(() => new HostName(null));
        }

        [Fact]
        public void TestCreateValidHostNameWhenPunyCode()
        {
            var host = new HostName("nic.xn--vermgensberater-ctb");

            Assert.Equal("nic.xn--vermgensberater-ctb", host.ToString());
            Assert.True(host.IsPunyCode);
            Assert.False(host.IsTld);
            Assert.Equal("xn--vermgensberater-ctb", host.Tld);
            Assert.Equal("nic.vermögensberater", host.ToUnicodeString());
        }

        [Fact]
        public void TestCreateValidHostNameWhenUnicode()
        {
            var host = new HostName("nic.vermögensberater");

            Assert.Equal("nic.xn--vermgensberater-ctb", host.ToString());
            Assert.True(host.IsPunyCode);
            Assert.False(host.IsTld);
            Assert.Equal("xn--vermgensberater-ctb", host.Tld);
            Assert.Equal("nic.vermögensberater", host.ToUnicodeString());
        }

        [Fact]
        public void TestCreateValidHostNameWhenHasMultipleSubdomains()
        {
            var host = new HostName("www.housekenya.co.ke");

            Assert.Equal("www.housekenya.co.ke", host.ToString());
            Assert.False(host.IsPunyCode);
            Assert.False(host.IsTld);
            Assert.Equal("ke", host.Tld);
            Assert.Equal("www.housekenya.co.ke", host.ToUnicodeString());
        }
    }
}
