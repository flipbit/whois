using System;
using System.Collections;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Whois.Net
{
    /// <summary>
    /// Class to allow access to TCP services
    /// </summary>
    public class TcpReader : ITcpReader, IDisposable
    {
        private readonly TcpClient tcpClient;

        private StreamReader reader;
        private StreamWriter writer;

        private async Task<bool> Connect(string domain, int port, Encoding encoding)
        {
            try
            {
                await tcpClient.ConnectAsync(domain, port);

                reader = new StreamReader(tcpClient.GetStream(), encoding);
                writer = new StreamWriter(tcpClient.GetStream())
                {
                    NewLine = "\r\n",
                };
            }
            catch (SocketException ex)
            {
                throw new WhoisException("Couldn't connect to " + domain + ": " + ex.Message, ex);
            }

            return tcpClient.Connected;
        }

        private async Task Write(string content)
        {
            try
            {
                await writer.WriteLineAsync(content);
                await writer.FlushAsync();
            }
            catch (Exception ex)
            {
                throw new WhoisException("Error whilst writing data: " + ex.Message);
            }
        }

        private async Task Read(StringBuilder sb)
        {
            try
            {
                var response = await reader.ReadLineAsync();

                while (response != null)
                {
                    sb.AppendLine(response);

                    response = await reader.ReadLineAsync();
                }
            }
            catch (Exception ex)
            {
                throw new WhoisException("Error whilst reading data: " + ex.Message);
            }
        } 

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpReader"/> class.
        /// </summary>
        public TcpReader()
        {
            tcpClient = new TcpClient();
        }

        public async Task<string> Read(string url, int port, string command, Encoding encoding)
        {
            var sb = new StringBuilder();

            var connected = await Connect(url, port, encoding);

            if (connected)
            {
                await Write(command);

                await Read(sb);
            }

            return sb.ToString();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (tcpClient?.Connected == true)
            {
                tcpClient.Close();
            }

#if !NET452
            tcpClient?.Dispose();
#endif
            reader?.Dispose();
            writer?.Dispose();
        }
    }
}