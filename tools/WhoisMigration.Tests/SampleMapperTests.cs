using Xunit;

namespace WhoisMigration.Tests;

public class SampleMapperTests
{
    [Theory]
    [InlineData("found.txt", "found", "found.txt")]
    [InlineData("found_nameservers_with_ip.txt", "found", "found_nameservers_with_ip.txt")]
    [InlineData("found_contact_person.txt", "found", "found_contact_person.txt")]
    [InlineData("found_status_registered.txt", "found", "found_status_registered.txt")]
    [InlineData("not_found.txt", "not-found", "not_found.txt")]
    [InlineData("not_found_status_available.txt", "not-found", "not_found_status_available.txt")]
    [InlineData("error.txt", "error", "error.txt")]
    [InlineData("invalid.txt", "invalid", "invalid.txt")]
    [InlineData("throttled.txt", "throttled", "throttled.txt")]
    [InlineData("reserved.txt", "reserved", "reserved.txt")]
    [InlineData("blocked.txt", "blocked", "blocked.txt")]
    [InlineData("suspended.txt", "suspended", "suspended.txt")]
    [InlineData("not_assigned.txt", "not-assigned", "not_assigned.txt")]
    [InlineData("inactive.txt", "inactive", "inactive.txt")]
    [InlineData("quarantined.txt", "quarantined", "quarantined.txt")]
    [InlineData("out_of_service.txt", "out-of-service", "out_of_service.txt")]
    [InlineData("to_be_released.txt", "to-be-released", "to_be_released.txt")]
    [InlineData("unavailable.txt", "unavailable", "unavailable.txt")]
    [InlineData("prohibited.txt", "prohibited", "prohibited.txt")]
    public void MapToStatusDirectory_extracts_status_and_preserves_filename(
        string input, string expectedStatus, string expectedFilename)
    {
        var (status, filename) = SampleMapper.MapToStatusDirectory(input);
        Assert.Equal(expectedStatus, status);
        Assert.Equal(expectedFilename, filename);
    }

    [Theory]
    [InlineData("adobe.com.txt", "found", "adobe.com.txt")]
    [InlineData("youtu.be.txt", "found", "youtu.be.txt")]
    [InlineData("unknown_status.txt", "found", "unknown_status.txt")]
    public void MapToStatusDirectory_falls_back_to_found_for_domain_named_samples(
        string input, string expectedStatus, string expectedFilename)
    {
        var (status, filename) = SampleMapper.MapToStatusDirectory(input);
        Assert.Equal(expectedStatus, status);
        Assert.Equal(expectedFilename, filename);
    }
}
