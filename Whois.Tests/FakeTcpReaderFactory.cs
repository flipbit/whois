using System.Text;
using Whois.Interfaces;

namespace Whois
{
    /// <summary>
    /// Returns <see cref="FakeTcpReader"/> objects for testing.
    /// </summary>
    internal class FakeTcpReaderFactory : ITcpReaderFactory 
    {
        public ITcpReader Create()
        {
            return new FakeTcpReader(Encoding.UTF8);
        }

        public ITcpReader Create(Encoding encoding)
        {
            return new FakeTcpReader(encoding);
        }
    }
}
