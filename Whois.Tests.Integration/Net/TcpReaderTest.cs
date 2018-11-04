using System;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Whois.Net
{
    /// <summary>
    /// These tests will only pass if your connected to the Internet
    /// </summary>
    [TestFixture]
    public class TcpReaderTest
    {
        [Test]
        public async Task TestReadWhoisForCogworksCoUk()
        {
            string result;

            using (var reader = new TcpReader())
            {
                result = await reader.Read("whois.nic.uk", 43, "cogworks.co.uk", Encoding.UTF8);
            }

            // Just check the domain name is in the response
            Assert.Greater(result.IndexOf("cogworks.co.uk"), -1);
        }

        [Test]
        [Ignore("Not working")]
        public async Task TestReadWhoisForSapoPt()
        {
            string result;

            using (var reader = new TcpReader())
            {
                result = await reader.Read("whois.dns.pt", 43, "sapo.pt", Encoding.GetEncoding("ISO-8859-1"));
            }

            // Just check the domain name is in the response
            Assert.Greater(result.IndexOf("sapo.pt"), -1);
        }

        [Test]
        public async Task TestReadWhoisForUolComBr()
        {
            string result;

            using (var reader = new TcpReader())
            {
                result = await reader.Read("registro.br", 43, "uol.com.br", Encoding.GetEncoding("ISO-8859-1"));
            }

            // Just check the domain name is in the response
            Assert.Greater(result.IndexOf("uol.com.br"), -1);
        }

        [Test]
        public async Task TestReadWhoisForUnknownDomain()
        {
            string result;

            using (var reader = new TcpReader())
            {
                result = await reader.Read("whois.nic.uk", 43, "invalid domain", Encoding.UTF8);
            }

            // SHould never be registered (as invalid)
            Assert.AreEqual(result.IndexOf("Registered on:"), -1);
        }

        [Test]
        public async Task TestReadWhenInvalidHost()
        {
            try
            {
                using (var reader = new TcpReader())
                {
                    await reader.Read("invalid domain", 43, "invalid domain", Encoding.UTF8);
                }

                Assert.Fail("Should of thrown an exception!");
            }
            catch (WhoisException)
            {
                // Should thrown an exception
            }
            catch (Exception)
            {
                Assert.Fail("Thrown an unexpected exception!");
            }
        }
    }
}
