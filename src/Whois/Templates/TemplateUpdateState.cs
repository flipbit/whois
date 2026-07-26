using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Whois.Templates;

/// <summary>
/// Tracks when the last template update check happened, whether it succeeded,
/// and when the next check is eligible (with exponential backoff on failure).
/// </summary>
// MA0182: Will be consumed by TemplatePackProvider (Task 7)  -  suppress until then.
#pragma warning disable MA0182
internal sealed class TemplateUpdateState
#pragma warning restore MA0182
{
    private const string StateFile = "update-state.json";
    private static readonly TimeSpan MaxPastAge = TimeSpan.FromDays(30);
    private const int MaxConsecutiveFailures = 10;

    private readonly CacheDirectoryManager _cache;
    private readonly ILogger<TemplateUpdateState> _logger;

    /// <summary>
    /// Backoff delay table indexed by (consecutiveFailures - 1), capped at index 3.
    /// </summary>
    public static readonly TimeSpan[] BackoffDelays =
    [
        TimeSpan.FromHours(1),
        TimeSpan.FromHours(4),
        TimeSpan.FromHours(24),
        TimeSpan.FromDays(7),
    ];

    public TemplateUpdateState(CacheDirectoryManager cache, ILogger<TemplateUpdateState> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public DateTimeOffset? LastCheckTime { get; private set; }
    public bool LastSuccess { get; private set; }
    public int ConsecutiveFailures { get; private set; }
    public string? CurrentVersion { get; private set; }

    /// <summary>
    /// In-memory only  -  disables eligibility for the current process lifetime without persisting.
    /// </summary>
    public bool DisabledForSession { get; set; }

    /// <summary>
    /// Reads state from disk. Resets implausible values to defaults.
    /// If the file is missing or corrupt, all fields remain at defaults.
    /// </summary>
    public void Load()
    {
        var bytes = _cache.ReadFile(StateFile);
        if (bytes is null)
            return;

        StateDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<StateDto>(bytes);
        }
#pragma warning disable CA1031 // Treat any deserialization failure as "corrupt  -  use defaults"
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger.LogWarning(ex, "Failed to deserialize update state; resetting to defaults");
            return;
        }

        if (dto is null)
            return;

        // Validate and apply each field independently so partial corruption resets only the bad field.
        var now = DateTimeOffset.UtcNow;

        if (dto.LastCheckTime.HasValue)
        {
            var t = dto.LastCheckTime.Value;
            if (t > now || (now - t) > MaxPastAge)
                _logger.LogDebug("Resetting implausible LastCheckTime {Time}", t);
            else
                LastCheckTime = t;
        }

        LastSuccess = dto.LastSuccess;

        if (dto.ConsecutiveFailures > MaxConsecutiveFailures)
        {
            _logger.LogDebug("Resetting implausible ConsecutiveFailures {Count}", dto.ConsecutiveFailures);
            ConsecutiveFailures = 0;
        }
        else
        {
            ConsecutiveFailures = dto.ConsecutiveFailures;
        }

        if (dto.CurrentVersion is not null)
        {
            if (TemplateVersion.TryParse(dto.CurrentVersion, out _))
                CurrentVersion = dto.CurrentVersion;
            else
                _logger.LogDebug("Resetting implausible CurrentVersion {Version}", dto.CurrentVersion);
        }
    }

    /// <summary>
    /// Persists the current state to disk. Does not persist <see cref="DisabledForSession"/>.
    /// </summary>
    public void Save()
    {
        var dto = new StateDto
        {
            LastCheckTime = LastCheckTime,
            LastSuccess = LastSuccess,
            ConsecutiveFailures = ConsecutiveFailures,
            CurrentVersion = CurrentVersion,
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(dto);
        _cache.WriteFile(StateFile, bytes);
    }

    /// <summary>
    /// Records a successful check: resets failure count, updates version and check time.
    /// </summary>
    public void RecordSuccess(string version, DateTimeOffset checkTime)
    {
        LastCheckTime = checkTime;
        LastSuccess = true;
        ConsecutiveFailures = 0;
        CurrentVersion = version;
    }

    /// <summary>
    /// Records a failed check: increments failure count and updates check time.
    /// </summary>
    public void RecordFailure(DateTimeOffset checkTime)
    {
        LastCheckTime = checkTime;
        LastSuccess = false;
        ConsecutiveFailures++;
    }

    /// <summary>
    /// Returns the earliest time at which the next check is eligible.
    /// Returns <see langword="null"/> if a check can happen immediately (no prior check recorded).
    /// Returns <see cref="DateTimeOffset.MaxValue"/> if <see cref="DisabledForSession"/> is true.
    /// </summary>
    public DateTimeOffset? GetNextEligibleTime(TimeSpan checkInterval)
    {
        if (DisabledForSession)
            return DateTimeOffset.MaxValue;

        if (LastCheckTime is null)
            return null;

        if (LastSuccess)
            return LastCheckTime.Value + checkInterval;

        // Failure backoff: index capped at 3
        var index = Math.Min(ConsecutiveFailures - 1, BackoffDelays.Length - 1);
        var delay = index >= 0 ? BackoffDelays[index] : BackoffDelays[0];
        return LastCheckTime.Value + delay;
    }

    /// <summary>
    /// Returns true if a check can be performed right now.
    /// </summary>
    public bool IsEligibleForCheck(TimeSpan checkInterval)
    {
        var next = GetNextEligibleTime(checkInterval);
        return next is null || next.Value <= DateTimeOffset.UtcNow;
    }

    // -------------------------------------------------------------------------
    // Private DTO for JSON serialization
    // -------------------------------------------------------------------------

    private sealed class StateDto
    {
        [JsonPropertyName("lastCheckTime")]
        public DateTimeOffset? LastCheckTime { get; set; }

        [JsonPropertyName("lastSuccess")]
        public bool LastSuccess { get; set; }

        [JsonPropertyName("consecutiveFailures")]
        public int ConsecutiveFailures { get; set; }

        [JsonPropertyName("currentVersion")]
        public string? CurrentVersion { get; set; }
    }
}
