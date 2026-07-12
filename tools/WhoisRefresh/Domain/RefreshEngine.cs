using System.Net.Sockets;
using System.Text;
using Whois.Net;
using Whois.Parsers;
using WhoisRefresh.Infrastructure;

namespace WhoisRefresh.Domain;

public record RefreshEngineOptions(
    string SamplesBasePath,
    TimeSpan DelayBetweenQueries,
    int QueryTimeoutSeconds,
    int MaxResponseBytes);

public class RefreshEngine
{
    private readonly ITcpReader _tcpReader;
    private readonly IFileSystem _fileSystem;

    public RefreshEngine(ITcpReader tcpReader, IFileSystem fileSystem)
    {
        _tcpReader = tcpReader;
        _fileSystem = fileSystem;
    }

    public async Task<RefreshResults> RunAsync(
        DomainRegistryData registry,
        RefreshEngineOptions options,
        CancellationToken cancellationToken)
    {
        var results = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new()
        };

        var groups = registry.GetRateGroups();

        var tasks = groups.Select(group =>
            ProcessRateGroupAsync(group, options, results, cancellationToken));

        await Task.WhenAll(tasks);

        return results;
    }

    private async Task ProcessRateGroupAsync(
        IGrouping<string, KeyValuePair<string, ServerEntry>> group,
        RefreshEngineOptions options,
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
                        await Task.Delay(options.DelayBetweenQueries, cancellationToken);
                    }
                    isFirst = false;

                    var domainResult = await QueryDomainAsync(
                        serverName, server.Tld, status, domain, options, cancellationToken);

                    RecordResult(results, serverName, server.Tld, status, domain, domainResult);
                }
            }
        }
    }

    private async Task<DomainResult> QueryDomainAsync(
        string serverName, string tld, string status, string domain,
        RefreshEngineOptions options, CancellationToken cancellationToken)
    {
        var result = new DomainResult
        {
            Timestamp = DateTimeOffset.UtcNow
        };

        try
        {
            var response = await _tcpReader.Read(
                serverName, 43, $"{domain}\r\n",
                Encoding.UTF8, options.QueryTimeoutSeconds, cancellationToken);

            if (response.Length > options.MaxResponseBytes)
            {
                result.Error = new QueryError
                {
                    Type = QueryErrorType.ResponseTooLarge,
                    Message = $"Response size {response.Length} exceeds maximum {options.MaxResponseBytes}",
                    Detail = $"{serverName}:43"
                };
                response = response[..options.MaxResponseBytes];
            }

            // Parse response
            var parser = new WhoisParser();
            var parsed = parser.Parse(serverName, response);

            result.MatchedTemplate = parsed.TemplateName;
            result.ExtractedFields = GetExtractedFieldNames(parsed);

            // Determine actual status for save directory
            var actualStatus = MapWhoisStatus(parsed.Status);
            var saveStatus = actualStatus ?? status;
            if (actualStatus != null && actualStatus != status)
            {
                result.ActualStatus = actualStatus;
            }

            // Save response to the actual status directory
            var dir = Path.Combine(options.SamplesBasePath, serverName, tld, saveStatus);
            if (!_fileSystem.DirectoryExists(dir))
            {
                _fileSystem.CreateDirectory(dir);
            }
            var filePath = Path.Combine(dir, $"{domain}.txt");
            await _fileSystem.WriteAllTextAsync(filePath, response, cancellationToken);

            if (result.Error == null && parsed.TemplateName == null)
            {
                result.Error = new QueryError
                {
                    Type = QueryErrorType.ParseFailure,
                    Message = "No template matched",
                    Detail = $"{serverName}/{tld}/{status}/{domain}"
                };
            }
        }
        catch (OperationCanceledException)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.Timeout,
                Message = "Query timed out",
                Detail = $"{serverName}:43"
            };
        }
        catch (SocketException ex)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.ConnectionRefused,
                Message = ex.Message,
                Detail = $"{serverName}:43"
            };
        }
        catch (Exception ex)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.Unknown,
                Message = ex.Message,
                Detail = $"{serverName}:43"
            };
        }

        return result;
    }

    private static List<string> GetExtractedFieldNames(Whois.WhoisResponse parsed)
    {
        var fields = new List<string>();
        if (parsed.DomainName != null) fields.Add("DomainName");
        if (parsed.Registrar != null) fields.Add("Registrar");
        if (parsed.Registered != null) fields.Add("Registered");
        if (parsed.Updated != null) fields.Add("Updated");
        if (parsed.Expiration != null) fields.Add("Expiration");
        if (parsed.NameServers.Count > 0) fields.Add("NameServers");
        if (parsed.DomainStatus.Count > 0) fields.Add("DomainStatus");
        if (parsed.Registrant != null) fields.Add("Registrant");
        if (parsed.TechnicalContact != null) fields.Add("TechnicalContact");
        if (parsed.AdminContact != null) fields.Add("AdminContact");
        if (parsed.BillingContact != null) fields.Add("BillingContact");
        if (parsed.DnsSecStatus != null) fields.Add("DnsSecStatus");
        if (parsed.RegistryDomainId != null) fields.Add("RegistryDomainId");
        return fields;
    }

    private static string? MapWhoisStatus(Whois.WhoisStatus status) => status switch
    {
        Whois.WhoisStatus.Found => "found",
        Whois.WhoisStatus.NotFound => "not-found",
        Whois.WhoisStatus.Throttled => "throttled",
        Whois.WhoisStatus.Reserved => "reserved",
        Whois.WhoisStatus.Suspended => "suspended",
        Whois.WhoisStatus.Inactive => "inactive",
        Whois.WhoisStatus.Expired => "expired",
        Whois.WhoisStatus.Blocked => "blocked",
        Whois.WhoisStatus.Deactivated => "deactivated",
        Whois.WhoisStatus.Error => "error",
        Whois.WhoisStatus.Failed => "failed",
        Whois.WhoisStatus.Invalid => "invalid",
        Whois.WhoisStatus.Locked => "locked",
        Whois.WhoisStatus.NotAssigned => "not-assigned",
        Whois.WhoisStatus.NotAvailable => "not-available",
        Whois.WhoisStatus.OutOfService => "out-of-service",
        Whois.WhoisStatus.PendingDelete => "pending-delete",
        Whois.WhoisStatus.Quarantined => "quarantined",
        Whois.WhoisStatus.Redemption => "redemption",
        Whois.WhoisStatus.ToBeReleased => "to-be-released",
        Whois.WhoisStatus.Unavailable => "unavailable",
        Whois.WhoisStatus.Unconfirmed => "unconfirmed",
        Whois.WhoisStatus.Unknown => null,
        _ => null
    };

    private static void RecordResult(
        RefreshResults results, string server, string tld, string status,
        string domain, DomainResult domainResult)
    {
        lock (results)
        {
            if (!results.Results.ContainsKey(server))
                results.Results[server] = new();
            if (!results.Results[server].ContainsKey(tld))
                results.Results[server][tld] = new();
            if (!results.Results[server][tld].ContainsKey(status))
                results.Results[server][tld][status] = new();

            results.Results[server][tld][status][domain] = domainResult;
        }
    }
}
