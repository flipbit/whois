using System.Text;

namespace Whois.Net
{
    /// <summary>
    /// Returns <see cref="FakeTcpReader"/> objects for testing.
    /// </summary>
    internal class FakeTcpReaderFactory : ITcpReaderFactory
    {
        public ITcpReader Reader { get; set; }

        public FakeTcpReaderFactory()
        {            
        }

        public FakeTcpReaderFactory(ITcpReader reader)
        {
            Reader = reader;
        }

        public ITcpReader Create()
        {
            return Reader;
        }

        public ITcpReader Create(Encoding encoding)
        {
            return Reader;
        }
    }
}
