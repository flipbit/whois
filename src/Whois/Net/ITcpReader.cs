using System;
using System.Text;
using System.Threading.Tasks;

namespace Whois.Net
{
    /// <summary>
    /// Interface to allow access to TCP services
    /// </summary>
    public interface ITcpReader : IDisposable
    {
        /// <summary>
        /// Reads data from the specified URL and port.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="port">The port.</param>
        /// <param name="command">The command.</param>
        /// <param name="encoding">The encoding to use whilst reading the server response.</param>
        /// <param name="timeoutSeconds">The network timeout in seconds</param>
        Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds);
    }
}