using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Tokens.Transformers;
using Tokens.Validators;
using Whois.Net;
using Whois.Parsers;
using Whois.Servers;

namespace Whois
{
    /// <summary>
    /// Looks up WHOIS information
    /// </summary>
    public class WhoisLookup : IWhoisLookup
    {
        private readonly ILogger<WhoisLookup> _logger;

        /// <summary>
        /// The default <see cref="WhoisOptions"/> to use for this instance
        /// </summary>
        public WhoisOptions Options { get; set; }

        /// <summary>
        /// The WHOIS parser that parses the free text WHOIS responses into
        /// structured C# objects
        /// </summary>
        public WhoisParser Parser { get; private set; }

        /// <summary>
        /// The WHOIS Server Lookup that finds root TLD servers for queries
        /// </summary>
        public IWhoisServerLookup ServerLookup { get; set; }

        /// <summary>
        /// The TCP reader that performs the network requests
        /// </summary>
        public ITcpReader TcpReader { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the default options
        /// </summary>
        public WhoisLookup() : this(new WhoisOptions())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the given <see cref="WhoisOptions"/>.
        /// </summary>
        public WhoisLookup(WhoisOptions options) : this(options, NullLogger<WhoisLookup>.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class for use with the Options pattern.
        /// </summary>
        public WhoisLookup(IOptions<WhoisOptions> options, ILogger<WhoisLookup> logger)
            : this(options.Value, logger)
        {
        }

        /// <summary>
        /// Full DI constructor — all dependencies supplied by the container.
        /// </summary>
        public WhoisLookup(IOptions<WhoisOptions> options, ILogger<WhoisLookup> logger, ITcpReader tcpReader, IWhoisServerLookup serverLookup)
        {
            Options = options.Value;
            _logger = logger;
            TcpReader = tcpReader;
            ServerLookup = serverLookup;
            Parser = new WhoisParser();
        }

        private WhoisLookup(WhoisOptions options, ILogger<WhoisLookup> logger)
        {
            Options = options;
            _logger = logger;
            Parser = new WhoisParser();
            TcpReader = new TcpReader();
            ServerLookup = new IanaServerLookup(TcpReader);
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        public Task<WhoisResponse> Lookup(string domain, CancellationToken cancellationToken = default)
        {
            return Lookup(domain, Options.Encoding, cancellationToken);
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        public Task<WhoisResponse> Lookup(string domain, Encoding encoding, CancellationToken cancellationToken = default)
        {
            return Lookup(new WhoisRequest
            {
                Query = domain,
                Encoding = encoding,
                TimeoutSeconds = Options.TimeoutSeconds,
                FollowReferrer = Options.FollowReferrer
            }, cancellationToken);
        }

        /// <summary>
        /// Performs a WHOIS lookup for the given request.
        /// </summary>
        public async Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(request.Query))
            {
                throw new ArgumentNullException($"{nameof(request)}.{nameof(request.Query)}");
            }

            // Trim leading '.'
            if (request.Query.StartsWith(".")) request.Query = request.Query.Substring(1);

            // Validate domain name
            if (HostName.TryParse(request.Query, out var hostName) == false)
            {
                throw new WhoisException($"WHOIS Query Format Error: {request.Query}");
            }

            _logger.LogDebug("Looking up WHOIS response for: {HostName}", hostName!.Value);

            // Set our starting point
            WhoisResponse response;
            if (string.IsNullOrEmpty(request.WhoisServer))
            {
                // Lookup root WHOIS server for the TLD
                response = await ServerLookup.Lookup(request, cancellationToken);
            }
            else
            {
                // Use the given WHOIS server
                response = WhoisResponse.WithServerUrl(request.WhoisServer!);
            }

            // If query is for a top level domain, we're finished
            if (hostName!.IsTld) return response;

            // Main loop: download & parse WHOIS data and follow the referrer chain
            var whoisServer = response.WhoisServer;
            while (whoisServer != null)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Download
                var content = await Download(whoisServer.Value, request, cancellationToken);

                // Parse result
                var parsed = Parser.Parse(whoisServer.Value, content);

                // Sanity check: ensure the last response has some data
                if (parsed.FieldsParsed == 0 && response.FieldsParsed > 0)
                {
                    break;
                }

                // Build referrer chain
                response = response.Chain(parsed);

                // Check for referral loop
                if (request.FollowReferrer == false) break;
                if (response.SeenServer(response.WhoisServer)) break;

                // Lookup result in referral server
                whoisServer = response.WhoisServer;
            }

            return response;
        }

        public void RegisterValidator<T>() where T : ITokenValidator
        {
            Parser.RegisterValidator<T>();
        }

        public void RegisterTransformer<T>() where T : ITokenTransformer
        {
            Parser.RegisterTransformer<T>();
        }

        private async Task<string> Download(string url, WhoisRequest request, CancellationToken cancellationToken)
        {
            // TODO: Expose this & extend for other TLDs
            var query = request.Query;
            if (query.EndsWith("jp")) query += "/e";    // Return English .jp results

            var content = await TcpReader.Read(url, 43, query, request.Encoding, request.TimeoutSeconds, cancellationToken);

            _logger.LogDebug("Lookup {Query}: Downloaded {ByteCount:###,###,##0} byte(s) from {Url}.", request.Query, content.Length, url);

            return content;
        }
    }
}
