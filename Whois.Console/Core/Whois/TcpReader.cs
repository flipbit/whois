using System;
using System.Collections;
using System.IO;
using System.Net.Sockets;
using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois
{
    /// <summary>
    /// Class to allow access to TCP services
    /// </summary>
    public class TcpReader : ITcpReader, IDisposable
    {
        #region Private

        private readonly TcpClient tcpClient;

        private StreamReader reader;
        private StreamWriter writer;

        private bool Connect(string domain, int port)
        {
            try
            {
                tcpClient.Connect(domain, port);

                reader = new StreamReader(tcpClient.GetStream());
                writer = new StreamWriter(tcpClient.GetStream()) { NewLine = "\r\n" };
            }
            catch (SocketException ex)
            {
                throw new ApplicationException("Couldn't connect to " + domain + ": " + ex.Message);
            }

            return tcpClient.Connected;
        }

        private void Write(string content)
        {
            try
            {
                writer.WriteLine(content);
                writer.Flush();
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error whilst writing data: " + ex.Message);
            }
        }

        private ArrayList Response()
        {
            var list = new ArrayList();

            try
            {
                var response = reader.ReadLine();

                while (response != null)
                {
                    list.Add(response);

                    response = reader.ReadLine();
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error whilst reading data: " + ex.Message);
            }

            return list;
        } 

        #endregion

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpReader"/> class.
        /// </summary>
        public TcpReader()
        {
            tcpClient = new TcpClient();
        }

        /// <summary>
        /// Reads the specified URL.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="port">The port.</param>
        /// <param name="command">The command.</param>
        /// <returns></returns>
        public ArrayList Read(string url, int port, string command)
        {
            var result = new ArrayList();

            var connected = Connect(url, port);

            if (connected)
            {
                Write(command);

                result = Response();
            }

            return result;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (tcpClient != null)
            {
                if (tcpClient.Connected)
                {
                    tcpClient.Close();
                }
            }
        }
    }
}