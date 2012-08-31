using System;
using System.Collections;
using System.Text;

namespace Flipbit.Core.Whois.Interfaces
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

        ArrayList Read(string url, int port, string command);
    }
}