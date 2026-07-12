using Xunit;

namespace WhoisMigration.Tests;

public class TemplateMapperTests
{
    [Theory]
    [InlineData("---\nname: whois.nic.tr/tr/Found\ntag: whois.nic.tr\nset: Status = Found\n---\n", "Found")]
    [InlineData("---\nname: whois.nic.tr/tr/NotFound\nset: Status = NotFound\n---\n", "NotFound")]
    [InlineData("---\nname: generic/tld/Throttled01\nset: Status = Throttled\n---\n", "Throttled")]
    [InlineData("---\n# Comment\nset:  Status  =  Reserved\n---\n", "Reserved")]
    public void ExtractStatus_returns_status_from_front_matter(string content, string expected)
    {
        var result = TemplateMapper.ExtractStatus(content);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ExtractStatus_throws_when_no_status_directive()
    {
        var content = "---\nname: test\ntag: test\n---\nNo status here";
        Assert.Throws<InvalidOperationException>(() => TemplateMapper.ExtractStatus(content));
    }

    [Theory]
    [InlineData("Found", "found")]
    [InlineData("NotFound", "not-found")]
    [InlineData("OutOfService", "out-of-service")]
    [InlineData("PendingDelete", "pending-delete")]
    [InlineData("ToBeReleased", "to-be-released")]
    [InlineData("NotAvailable", "not-available")]
    [InlineData("NotAssigned", "not-assigned")]
    [InlineData("Throttled", "throttled")]
    [InlineData("Error", "error")]
    public void ToStatusDirectory_converts_pascal_case_to_kebab_case(string input, string expected)
    {
        var result = TemplateMapper.ToStatusDirectory(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void AssignNumbers_assigns_sequential_numbers_alphabetically()
    {
        var filenames = new List<string> { "Found01", "Found", "Found02" };
        var result = TemplateMapper.AssignNumbers(filenames);

        Assert.Equal("01", result["Found"]);
        Assert.Equal("02", result["Found01"]);
        Assert.Equal("03", result["Found02"]);
    }

    [Fact]
    public void AssignNumbers_single_file_gets_01()
    {
        var filenames = new List<string> { "NotFound" };
        var result = TemplateMapper.AssignNumbers(filenames);

        Assert.Equal("01", result["NotFound"]);
    }

    [Fact]
    public void AssignNumbers_handles_mixed_variants()
    {
        var filenames = new List<string> { "FoundRegistered", "Found", "FoundV1" };
        var result = TemplateMapper.AssignNumbers(filenames);

        Assert.Equal("01", result["Found"]);
        Assert.Equal("02", result["FoundRegistered"]);
        Assert.Equal("03", result["FoundV1"]);
    }

    [Fact]
    public void UpdateFrontMatterName_replaces_name_in_front_matter()
    {
        var content = "---\n#\n# .tr Parsing Template\n#\nname: whois.nic.tr/tr/Found\ntag: whois.nic.tr\nset: Status = Found\n---\nContent here";
        var result = TemplateMapper.UpdateFrontMatterName(content, "whois.nic.tr/tr/found/01");

        Assert.Contains("name: whois.nic.tr/tr/found/01", result, StringComparison.Ordinal);
        Assert.DoesNotContain("name: whois.nic.tr/tr/Found", result, StringComparison.Ordinal);
        Assert.Contains("Content here", result, StringComparison.Ordinal);
    }

    [Fact]
    public void UpdateFrontMatterName_preserves_other_front_matter()
    {
        var content = "---\nname: old/name\ntag: whois.nic.tr\ntag: tr\nset: Status = Found\n---\n";
        var result = TemplateMapper.UpdateFrontMatterName(content, "new/name");

        Assert.Contains("tag: whois.nic.tr", result, StringComparison.Ordinal);
        Assert.Contains("tag: tr", result, StringComparison.Ordinal);
        Assert.Contains("set: Status = Found", result, StringComparison.Ordinal);
    }
}
