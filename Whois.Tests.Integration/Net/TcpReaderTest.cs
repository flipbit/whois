using System;
using System.Text;
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
        public void TestReadWhoisForCogworksCoUk()
        {
            string result;

            using (var reader = new TcpReader())
            {
                result = reader.Read("whois.nic.uk", 43, "cogworks.co.uk");
            }

            // Just check the domain name is in the response
            Assert.Greater(result.IndexOf("cogworks.co.uk"), -1);
        }

        [Test]
        [Ignore]
        public void TestReadWhoisForSapoPt()
        {
            string result;
            var encoding = Encoding.GetEncoding("ISO-8859-1");

            using (var reader = new TcpReader(encoding))
            {
                result = reader.Read("whois.dns.pt", 43, "sapo.pt");
            }

            // Just check the domain name is in the response
            Assert.Greater(result.IndexOf("sapo.pt"), -1);
        }

        [Test]
        public void TestReadWhoisForUolComBr()
        {
            string result;
            var encoding = Encoding.GetEncoding("ISO-8859-1");

            using (var reader = new TcpReader(encoding))
            {
                result = reader.Read("registro.br", 43, "uol.com.br");
            }

            // Just check the domain name is in the response
            Assert.Greater(result.IndexOf("uol.com.br"), -1);
        }

        [Test]
        public void TestReadWhoisForUnknownDomain()
        {
            string result;

            using (var reader = new TcpReader())
            {
                result = reader.Read("whois.nic.uk", 43, "invalid domain");
            }

            // SHould never be registered (as invalid)
            Assert.AreEqual(result.IndexOf("Registered on:"), -1);
        }

        [Test]
        public void TestReadWhenInvalidHost()
        {
            try
            {
                using (var reader = new TcpReader())
                {
                    reader.Read("invalid domain", 43, "invalid domain");
                }

                Assert.Fail("Should of thrown an exception!");
            }
            catch (ApplicationException)
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
