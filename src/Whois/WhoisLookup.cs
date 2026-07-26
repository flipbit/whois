using Microsoft.Extensions.Logging.Abstractions;
using Whois.Parsers;
using Whois.Templates;

namespace Whois;

/// <summary>
/// Looks up WHOIS information
/// </summary>
public class WhoisLookup : IWhoisLookup
{
    // Static shared instances for non-DI use -- created lazily.
    private static readonly Lazy<TemplatePackProvider> SharedPackProvider = new(() =>
    {
        var options = new WhoisOptions();
        var cacheDir = GetDefaultCacheDirectory();
        var cacheLogger = NullLogger<CacheDirectoryManager>.Instance;
        var stateLogger = NullLogger<TemplateUpdateState>.Instance;
        var cache = new CacheDirectoryManager(cacheDir, cacheLogger);
        var state = new TemplateUpdateState(cache, stateLogger);
        return new TemplatePackProvider(options, NullLogger<TemplatePackProvider>.Instance, cache, state);
    });

    private readonly ITemplatePackProvider _packProvider;

    /// <summary>
    /// The default <see cref="WhoisOptions"/> to use for this instance
    /// </summary>
    public WhoisOptions Options { get; set; } = new WhoisOptions();

    /// <summary>
    /// Reports the current state of the template cache.
    /// </summary>
    public TemplateStatus TemplateStatus => _packProvider.Status;

    /// <summary>
    /// Checks for and applies template updates from the configured release URL.
    /// </summary>
    public Task<TemplateUpdateResult> UpdateTemplates(CancellationToken cancellationToken = default) =>
        _packProvider.CheckForUpdate(cancellationToken);

    /// <summary>
    /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the default options.
    /// </summary>
    public WhoisLookup()
    {
        _packProvider = SharedPackProvider.Value;
    }

    /// <summary>
    /// Internal constructor for testing -- accepts explicit pack provider and parser.
    /// </summary>
    internal WhoisLookup(ITemplatePackProvider packProvider, WhoisParser parser)
    {
        _packProvider = packProvider;
        _ = parser; // parser used by Task 8 implementation
    }

    // Temporary stub -- full implementation in Task 8
    public Task<LookupResult<DomainInfo>> Lookup(string domain, CancellationToken ct = default)
        => throw new NotImplementedException();

    public Task<LookupResult<DomainInfo>> Lookup(WhoisRequest request, CancellationToken ct = default)
        => throw new NotImplementedException();

    private static string GetDefaultCacheDirectory() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Whois",
            "templates");
}
