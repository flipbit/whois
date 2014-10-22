using System;
using System.Collections;
using System.Text;
using System.IO;
using System.Net.Sockets;
using Whois.Interfaces;

namespace Whois.Net
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

                reader = new StreamReader(tcpClient.GetStream(), CurrentEncoding);
                writer = new StreamWriter(tcpClient.GetStream())
                {
                    NewLine = "\r\n",
                };
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

        private void Read(StringBuilder sb)
        {
            try
            {
                var response = reader.ReadLine();

                while (response != null)
                {
                    sb.AppendLine(response);

                    response = reader.ReadLine();
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error whilst reading data: " + ex.Message);
            }
        } 

        #endregion

        /// <summary>
        /// Gets the current character encoding that the current TcpReader
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current reader.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpReader"/> class.
        /// </summary>
        public TcpReader() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpReader"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public TcpReader(Encoding encoding)
        {
            tcpClient = new TcpClient();

            CurrentEncoding = encoding;
        }

        /// <summary>
        /// Reads the specified URL.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="port">The port.</param>
        /// <param name="command">The command.</param>
        /// <returns></returns>
        public string Read(string url, int port, string command)
        {
            var sb = new StringBuilder();

            var connected = Connect(url, port);

            if (connected)
            {
                Write(command);

                Read(sb);
            }

            return sb.ToString();
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