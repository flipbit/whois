using System;
using System.Collections;

namespace Flipbit.Core.Whois.Interfaces
{
    /// <summary>
    /// Interface to allow access to TCP services
    /// </summary>
    public interface ITcpReader : IDisposable
    {
        ArrayList Read(string url, int port, string command);
    }
}