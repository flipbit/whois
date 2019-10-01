using System.Collections;
using System.Text;
using System.Threading.Tasks;

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
        
        public Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds)
        {
            return Task.FromResult(response);
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