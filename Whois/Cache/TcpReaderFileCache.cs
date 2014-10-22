using System.Text;
using Whois.Net;

namespace Whois.Cache
{
    /// <summary>
    /// Class that caches results of TCP Reads in the users profile directory
    /// </summary>
    public class TcpReaderFileCache : ITcpReader
    {
        /// <summary>
        /// Gets or sets the actual TCP Reader.
        /// </summary>
        /// <value>
        /// The actual.
        /// </value>
        public ITcpReader Actual { get; set; }

        /// <summary>
        /// Gets or sets the file store.
        /// </summary>
        /// <value>
        /// The file store.
        /// </value>
        public IFileStore FileStore { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpReaderFileCache"/> class.
        /// </summary>
        public TcpReaderFileCache()
        {
            Actual = new TcpReader();
            FileStore = new FileStore();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Actual.Dispose();
        }

        /// <summary>
        /// Gets the current character encoding that the current TcpReader
        /// object is using.
        /// </summary>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Reads data from the specified URL and port.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="port">The port.</param>
        /// <param name="command">The command.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public string Read(string url, int port, string command)
        {
            var result = FileStore.Read(url, command);

            if (string.IsNullOrEmpty(result))
            {
                result = Actual.Read(url, port, command);

                FileStore.Write(url, command, result);
            }

            return result;
        }
    }
}
