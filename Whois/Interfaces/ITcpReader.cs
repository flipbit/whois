using System;
using System.Collections;
using System.Text;

namespace Whois.Interfaces
{
    /// <summary>
    /// Interface to allow access to TCP services
    /// </summary>
    public interface ITcpReader : IDisposable
    {
        /// <summary>
        /// Gets the current character encoding that the current TcpReader
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current reader.</returns>
        Encoding CurrentEncoding { get; }

        /// <summary>
        /// Reads data from the specified URL and port.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="port">The port.</param>
        /// <param name="command">The command.</param>
        /// <returns></returns>
        ArrayList Read(string url, int port, string command);
    }
}