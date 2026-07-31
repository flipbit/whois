using System.Globalization;
using Whois.Protocols;

namespace Whois.Refresh.Domain;

public record RdapRefreshEngineOptions(
    TimeSpan DelayBetweenQueries,
    int QueryTimeoutSeconds);

public class RdapRefreshEngine
{
    private const int HttpTooManyRequests = 429;

    private readonly HttpClient _httpClient;

    public RdapRefreshEngine(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<RefreshResults> RunAsync(
        DomainRegistryData registry,
        RdapRefreshEngineOptions options,
        CancellationToken cancellationToken)
    {
        var results = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>>(StringComparer.Ordinal),
        };

        var groups = registry.GetRateGroups();

        var tasks = groups.Select(group =>
            ProcessRateGroupAsync(group, options, results, cancellationToken));

        await Task.WhenAll(tasks).ConfigureAwait(false);

        return results;
    }

    private async Task ProcessRateGroupAsync(
        IGrouping<string, KeyValuePair<string, ServerEntry>> group,
        RdapRefreshEngineOptions options,
        RefreshResults results,
        CancellationToken cancellationToken)
    {
        var isFirst = true;

        foreach (var (serverName, server) in group)
        {
            foreach (var (status, domains) in server.Domains)
            {
                foreach (var domain in domains)
                {
                    if (!isFirst && options.DelayBetweenQueries > TimeSpan.Zero)
                    {
                        await Task.Delay(options.DelayBetweenQueries, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    isFirst = false;

                    var domainResult = await QueryDomainAsync(
                        serverName, server, status, domain, options, cancellationToken)
                        .ConfigureAwait(false);

                    RecordResult(results, serverName, server.Tld, status, domain, domainResult);
                }
            }
        }
    }

    private async Task<DomainResult> QueryDomainAsync(
        string serverName, ServerEntry server, string status, string domain,
        RdapRefreshEngineOptions options, CancellationToken cancellationToken)
    {
        var result = new DomainResult
        {
            Timestamp = DateTimeOffset.UtcNow,
        };

        if (server.RdapBaseUrl == null)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.Unknown,
                Message = "No rdapBaseUrl configured for server",
                Detail = serverName,
            };
            return result;
        }

        var encodedDomain = Uri.EscapeDataString(domain);
        var url = $"{server.RdapBaseUrl.TrimEnd('/')}/domain/{encodedDomain}";

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(options.QueryTimeoutSeconds));

            using var response = await _httpClient.GetAsync(url, cts.Token).ConfigureAwait(false);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                result.ActualStatus = DomainRegistry.MapRegistrationStatus(
                    Whois.RegistrationStatus.NotFound);
                return result;
            }

            if ((int)response.StatusCode == HttpTooManyRequests)
            {
                result.Error = new QueryError
                {
                    Type = QueryErrorType.RateLimited,
                    Message = "Rate limited (HTTP 429)",
                    Detail = url,
                };
                return result;
            }

            if (!response.IsSuccessStatusCode)
            {
                result.Error = new QueryError
                {
                    Type = QueryErrorType.Unknown,
                    Message = string.Format(CultureInfo.InvariantCulture,
                        "HTTP {0}", (int)response.StatusCode),
                    Detail = url,
                };
                return result;
            }

            var json = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var parsed = RdapParser.Parse(json);

            result.ExtractedFields = GetExtractedFieldNames(parsed);

            var actualStatus = DomainRegistry.MapRegistrationStatus(parsed.Status);
            if (actualStatus != null
                && !string.Equals(actualStatus, status, StringComparison.OrdinalIgnoreCase))
            {
                result.ActualStatus = actualStatus;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.Timeout,
                Message = "Query timed out",
                Detail = url,
            };
        }
        catch (HttpRequestException ex)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.ConnectionRefused,
                Message = ex.Message,
                Detail = url,
            };
        }
#pragma warning disable CA1031 // Catch-all for RDAP queries; classify as unknown error
        catch (Exception ex)
#pragma warning restore CA1031
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.Unknown,
                Message = ex.Message,
                Detail = url,
            };
        }

        return result;
    }

    private static List<string> GetExtractedFieldNames(DomainInfo parsed)
    {
        var fields = new List<string>();
        if (parsed.DomainName != null) fields.Add("DomainName");
        if (parsed.RegistryDomainId != null) fields.Add("RegistryDomainId");
        if (parsed.Registrar != null) fields.Add("Registrar");
        if (parsed.Registered.HasValue) fields.Add("Registered");
        if (parsed.Updated.HasValue) fields.Add("Updated");
        if (parsed.Expiration.HasValue) fields.Add("Expiration");
        if (parsed.NameServers.Count > 0) fields.Add("NameServers");
        if (parsed.DomainStatus.Count > 0) fields.Add("DomainStatus");
        if (parsed.Registrant != null) fields.Add("Registrant");
        if (parsed.TechnicalContact != null) fields.Add("TechnicalContact");
        if (parsed.AdminContact != null) fields.Add("AdminContact");
        if (parsed.BillingContact != null) fields.Add("BillingContact");
        return fields;
    }

    private static void RecordResult(
        RefreshResults results, string server, string tld, string status,
        string domain, DomainResult domainResult)
    {
        lock (results)
        {
            if (!results.Results.ContainsKey(server))
                results.Results[server] = new Dictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>(StringComparer.Ordinal);
            if (!results.Results[server].ContainsKey(tld))
                results.Results[server][tld] = new Dictionary<string, IDictionary<string, DomainResult>>(StringComparer.Ordinal);
            if (!results.Results[server][tld].ContainsKey(status))
                results.Results[server][tld][status] = new Dictionary<string, DomainResult>(StringComparer.Ordinal);

            results.Results[server][tld][status][domain] = domainResult;
        }
    }
}
