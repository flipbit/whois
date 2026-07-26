using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Whois.Templates;

namespace Whois.Tests.Templates;

/// <summary>
/// Tests for TemplateUpdateState using real temp directories via CacheDirectoryManager.
/// </summary>
public class TemplateUpdateStateTests : IDisposable
{
    private readonly string _tempDir;
    private readonly CacheDirectoryManager _cache;
    private readonly TemplateUpdateState _state;

    public TemplateUpdateStateTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "whois-update-state-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _cache = new CacheDirectoryManager(_tempDir, NullLogger<CacheDirectoryManager>.Instance);
        _state = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    // -------------------------------------------------------------------------
    // Default state
    // -------------------------------------------------------------------------

    [Fact]
    public void DefaultState_AllValuesAreDefaults()
    {
        Assert.Null(_state.LastCheckTime);
        Assert.False(_state.LastSuccess);
        Assert.Equal(0, _state.ConsecutiveFailures);
        Assert.Null(_state.CurrentVersion);
        Assert.False(_state.DisabledForSession);
    }

    // -------------------------------------------------------------------------
    // Load  -  missing file
    // -------------------------------------------------------------------------

    [Fact]
    public void Load_MissingFile_RemainsDefaults()
    {
        _state.Load();

        Assert.Null(_state.LastCheckTime);
        Assert.False(_state.LastSuccess);
        Assert.Equal(0, _state.ConsecutiveFailures);
        Assert.Null(_state.CurrentVersion);
    }

    // -------------------------------------------------------------------------
    // Save / Load round-trip
    // -------------------------------------------------------------------------

    [Fact]
    public void SaveLoad_RoundTrips_SuccessState()
    {
        var checkTime = new DateTimeOffset(2026, 7, 12, 10, 0, 0, TimeSpan.Zero);
        _state.RecordSuccess("2026.07.12.1", checkTime);
        _state.Save();

        var loaded = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
        loaded.Load();

        Assert.Equal(checkTime, loaded.LastCheckTime);
        Assert.True(loaded.LastSuccess);
        Assert.Equal(0, loaded.ConsecutiveFailures);
        Assert.Equal("2026.07.12.1", loaded.CurrentVersion);
    }

    [Fact]
    public void SaveLoad_RoundTrips_FailureState()
    {
        var checkTime = new DateTimeOffset(2026, 7, 12, 10, 0, 0, TimeSpan.Zero);
        _state.RecordFailure(checkTime);
        _state.RecordFailure(checkTime.AddHours(1));
        _state.Save();

        var loaded = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
        loaded.Load();

        Assert.Equal(checkTime.AddHours(1), loaded.LastCheckTime);
        Assert.False(loaded.LastSuccess);
        Assert.Equal(2, loaded.ConsecutiveFailures);
    }

    // -------------------------------------------------------------------------
    // Load  -  corrupt JSON
    // -------------------------------------------------------------------------

    [Fact]
    public void Load_CorruptJson_ResetsToDefaults()
    {
        _cache.WriteFile("update-state.json", "not valid json"u8.ToArray());

        _state.Load();

        Assert.Null(_state.LastCheckTime);
        Assert.False(_state.LastSuccess);
        Assert.Equal(0, _state.ConsecutiveFailures);
        Assert.Null(_state.CurrentVersion);
    }

    // -------------------------------------------------------------------------
    // Load  -  implausible value: ConsecutiveFailures > 10
    // -------------------------------------------------------------------------

    [Fact]
    public void Load_ExcessiveConsecutiveFailures_ResetsToZero()
    {
        var json = """{"lastCheckTime":"2026-07-12T10:00:00Z","lastSuccess":false,"consecutiveFailures":99,"currentVersion":"2026.07.12.1"}""";
        _cache.WriteFile("update-state.json", System.Text.Encoding.UTF8.GetBytes(json));

        _state.Load();

        Assert.Equal(0, _state.ConsecutiveFailures);
    }

    // -------------------------------------------------------------------------
    // Load  -  implausible value: LastCheckTime more than 30 days in the past
    // -------------------------------------------------------------------------

    [Fact]
    public void Load_LastCheckTimeTooOld_ResetsToNull()
    {
        var oldTime = DateTimeOffset.UtcNow.AddDays(-31).ToString("o");
        var json = $$"""{"lastCheckTime":"{{oldTime}}","lastSuccess":true,"consecutiveFailures":0,"currentVersion":"2026.07.12.1"}""";
        _cache.WriteFile("update-state.json", System.Text.Encoding.UTF8.GetBytes(json));

        _state.Load();

        Assert.Null(_state.LastCheckTime);
    }

    // -------------------------------------------------------------------------
    // Load  -  implausible value: LastCheckTime in the future
    // -------------------------------------------------------------------------

    [Fact]
    public void Load_LastCheckTimeInFuture_ResetsToNull()
    {
        var futureTime = DateTimeOffset.UtcNow.AddDays(1).ToString("o");
        var json = $$"""{"lastCheckTime":"{{futureTime}}","lastSuccess":true,"consecutiveFailures":0,"currentVersion":"2026.07.12.1"}""";
        _cache.WriteFile("update-state.json", System.Text.Encoding.UTF8.GetBytes(json));

        _state.Load();

        Assert.Null(_state.LastCheckTime);
    }

    // -------------------------------------------------------------------------
    // Load  -  implausible value: bad version string
    // -------------------------------------------------------------------------

    [Fact]
    public void Load_BadVersionString_ResetsVersionToNull()
    {
        var json = """{"lastCheckTime":"2026-07-12T10:00:00Z","lastSuccess":true,"consecutiveFailures":0,"currentVersion":"not-a-version"}""";
        _cache.WriteFile("update-state.json", System.Text.Encoding.UTF8.GetBytes(json));

        _state.Load();

        Assert.Null(_state.CurrentVersion);
        // Other fields that are valid should be preserved
        Assert.NotNull(_state.LastCheckTime);
        Assert.True(_state.LastSuccess);
    }

    // -------------------------------------------------------------------------
    // RecordSuccess
    // -------------------------------------------------------------------------

    [Fact]
    public void RecordSuccess_SetsVersionAndClearsFailures()
    {
        var checkTime = new DateTimeOffset(2026, 7, 12, 10, 0, 0, TimeSpan.Zero);
        _state.RecordFailure(checkTime.AddHours(-2));
        _state.RecordFailure(checkTime.AddHours(-1));

        _state.RecordSuccess("2026.07.12.1", checkTime);

        Assert.Equal("2026.07.12.1", _state.CurrentVersion);
        Assert.Equal(checkTime, _state.LastCheckTime);
        Assert.True(_state.LastSuccess);
        Assert.Equal(0, _state.ConsecutiveFailures);
    }

    // -------------------------------------------------------------------------
    // RecordFailure
    // -------------------------------------------------------------------------

    [Fact]
    public void RecordFailure_IncrementsConsecutiveFailures()
    {
        var t1 = new DateTimeOffset(2026, 7, 12, 10, 0, 0, TimeSpan.Zero);
        var t2 = t1.AddHours(1);

        _state.RecordFailure(t1);
        Assert.Equal(1, _state.ConsecutiveFailures);
        Assert.Equal(t1, _state.LastCheckTime);
        Assert.False(_state.LastSuccess);

        _state.RecordFailure(t2);
        Assert.Equal(2, _state.ConsecutiveFailures);
        Assert.Equal(t2, _state.LastCheckTime);
    }

    // -------------------------------------------------------------------------
    // BackoffDelays constant
    // -------------------------------------------------------------------------

    [Fact]
    public void BackoffDelays_HasCorrectValues()
    {
        Assert.Equal(TimeSpan.FromHours(1), TemplateUpdateState.BackoffDelays[0]);
        Assert.Equal(TimeSpan.FromHours(4), TemplateUpdateState.BackoffDelays[1]);
        Assert.Equal(TimeSpan.FromHours(24), TemplateUpdateState.BackoffDelays[2]);
        Assert.Equal(TimeSpan.FromDays(7), TemplateUpdateState.BackoffDelays[3]);
    }

    // -------------------------------------------------------------------------
    // GetNextEligibleTime  -  DisabledForSession
    // -------------------------------------------------------------------------

    [Fact]
    public void GetNextEligibleTime_DisabledForSession_ReturnsMaxValue()
    {
        _state.DisabledForSession = true;

        var result = _state.GetNextEligibleTime(TimeSpan.FromHours(24));

        Assert.Equal(DateTimeOffset.MaxValue, result);
    }

    // -------------------------------------------------------------------------
    // GetNextEligibleTime  -  no last check time
    // -------------------------------------------------------------------------

    [Fact]
    public void GetNextEligibleTime_NoLastCheckTime_ReturnsNull()
    {
        var result = _state.GetNextEligibleTime(TimeSpan.FromHours(24));

        Assert.Null(result);
    }

    // -------------------------------------------------------------------------
    // GetNextEligibleTime  -  after success
    // -------------------------------------------------------------------------

    [Fact]
    public void GetNextEligibleTime_AfterSuccess_ReturnsLastCheckPlusInterval()
    {
        var checkTime = new DateTimeOffset(2026, 7, 12, 10, 0, 0, TimeSpan.Zero);
        var interval = TimeSpan.FromHours(24);
        _state.RecordSuccess("2026.07.12.1", checkTime);

        var result = _state.GetNextEligibleTime(interval);

        Assert.Equal(checkTime + interval, result);
    }

    // -------------------------------------------------------------------------
    // GetNextEligibleTime  -  backoff after failures
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(1, 1)]   // 1 failure -> 1 hour
    [InlineData(2, 4)]   // 2 failures -> 4 hours
    [InlineData(3, 24)]  // 3 failures -> 24 hours
    [InlineData(4, 168)] // 4 failures -> 7 days = 168 hours
    [InlineData(5, 168)] // 5+ failures -> still 7 days (capped)
    [InlineData(10, 168)]
    public void GetNextEligibleTime_AfterFailures_UsesBackoffDelay(int failureCount, int expectedHours)
    {
        var checkTime = new DateTimeOffset(2026, 7, 12, 10, 0, 0, TimeSpan.Zero);
        for (var i = 0; i < failureCount; i++)
            _state.RecordFailure(checkTime.AddMinutes(i));

        var result = _state.GetNextEligibleTime(TimeSpan.FromHours(24));

        var expectedDelay = TimeSpan.FromHours(expectedHours);
        // last failure time is checkTime + (failureCount-1) minutes
        var lastFailureTime = checkTime.AddMinutes(failureCount - 1);
        Assert.Equal(lastFailureTime + expectedDelay, result);
    }

    // -------------------------------------------------------------------------
    // IsEligibleForCheck
    // -------------------------------------------------------------------------

    [Fact]
    public void IsEligibleForCheck_NoLastCheckTime_ReturnsTrue()
    {
        Assert.True(_state.IsEligibleForCheck(TimeSpan.FromHours(24)));
    }

    [Fact]
    public void IsEligibleForCheck_DisabledForSession_ReturnsFalse()
    {
        _state.DisabledForSession = true;

        Assert.False(_state.IsEligibleForCheck(TimeSpan.FromHours(24)));
    }

    [Fact]
    public void IsEligibleForCheck_RecentSuccess_ReturnsFalse()
    {
        var checkTime = DateTimeOffset.UtcNow.AddMinutes(-30);
        _state.RecordSuccess("2026.07.12.1", checkTime);

        // 24h interval  -  we checked 30 minutes ago so not eligible
        Assert.False(_state.IsEligibleForCheck(TimeSpan.FromHours(24)));
    }

    [Fact]
    public void IsEligibleForCheck_OldSuccess_ReturnsTrue()
    {
        var checkTime = DateTimeOffset.UtcNow.AddHours(-25);
        _state.RecordSuccess("2026.07.12.1", checkTime);

        // 24h interval  -  we checked 25 hours ago so eligible
        Assert.True(_state.IsEligibleForCheck(TimeSpan.FromHours(24)));
    }

    [Fact]
    public void IsEligibleForCheck_RecentFailure_ReturnsFalse()
    {
        // 1 failure -> 1 hour backoff; failure was 30 min ago -> not eligible
        var checkTime = DateTimeOffset.UtcNow.AddMinutes(-30);
        _state.RecordFailure(checkTime);

        Assert.False(_state.IsEligibleForCheck(TimeSpan.FromHours(24)));
    }

    [Fact]
    public void IsEligibleForCheck_OldFailure_ReturnsTrue()
    {
        // 1 failure -> 1 hour backoff; failure was 2 hours ago -> eligible
        var checkTime = DateTimeOffset.UtcNow.AddHours(-2);
        _state.RecordFailure(checkTime);

        Assert.True(_state.IsEligibleForCheck(TimeSpan.FromHours(24)));
    }

    // -------------------------------------------------------------------------
    // DisabledForSession not persisted
    // -------------------------------------------------------------------------

    [Fact]
    public void DisabledForSession_NotPersisted()
    {
        var checkTime = new DateTimeOffset(2026, 7, 12, 10, 0, 0, TimeSpan.Zero);
        _state.RecordSuccess("2026.07.12.1", checkTime);
        _state.DisabledForSession = true;
        _state.Save();

        var loaded = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
        loaded.Load();

        Assert.False(loaded.DisabledForSession);
    }
}
