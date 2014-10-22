using System.Collections;
using System.Text;

namespace Whois.Net
{
    /// <summary>
    /// Fakes out TCP responses for testing
    /// </summary>
    internal class FakeTcpReader : ITcpReader
    {
        public Encoding CurrentEncoding { get; private set; }

        private string response;

        public FakeTcpReader(string response)
        {
            this.response = response;
        }
        
        public string Read(string url, int port, string command)
        {
            return response;
        }

        private string EncodeResponse(string fakeResponse, Encoding srcEncoding, Encoding dstEncoding)
        {
            var convertedBytes = Encoding.Convert(srcEncoding, dstEncoding,
                srcEncoding.GetBytes(fakeResponse));

            return CurrentEncoding.GetString(convertedBytes);
        }

        public void Dispose()
        {
        }
    }
}