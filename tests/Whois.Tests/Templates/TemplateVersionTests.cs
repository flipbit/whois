using Xunit;
using Whois.Templates;

namespace Whois.Tests.Templates;

public class TemplateVersionTests
{
    [Fact]
    public void TryParse_ValidVersion_ReturnsTrue()
    {
        var result = TemplateVersion.TryParse("2026.07.12.1", out var components);

        Assert.True(result);
        Assert.NotNull(components);
        Assert.Equal(new[] { 2026, 7, 12, 1 }, components);
    }

    [Fact]
    public void TryParse_NonZeroPaddedComponents_ReturnsTrue()
    {
        var result = TemplateVersion.TryParse("2026.7.1.1", out var components);

        Assert.True(result);
        Assert.NotNull(components);
        Assert.Equal(new[] { 2026, 7, 1, 1 }, components);
    }

    [Fact]
    public void TryParse_AlphaString_ReturnsFalse()
    {
        var result = TemplateVersion.TryParse("abc", out var components);

        Assert.False(result);
        Assert.Null(components);
    }

    [Fact]
    public void TryParse_TooFewComponents_ReturnsFalse()
    {
        var result = TemplateVersion.TryParse("2026.07", out var components);

        Assert.False(result);
        Assert.Null(components);
    }

    [Fact]
    public void TryParse_TooManyComponents_ReturnsFalse()
    {
        var result = TemplateVersion.TryParse("2026.07.12.1.5", out var components);

        Assert.False(result);
        Assert.Null(components);
    }

    [Fact]
    public void TryParse_EmptyString_ReturnsFalse()
    {
        var result = TemplateVersion.TryParse("", out var components);

        Assert.False(result);
        Assert.Null(components);
    }

    [Fact]
    public void TryParse_NullString_ReturnsFalse()
    {
        var result = TemplateVersion.TryParse(null!, out var components);

        Assert.False(result);
        Assert.Null(components);
    }

    [Fact]
    public void Compare_HigherFirst_ReturnsPositive()
    {
        var a = new[] { 2026, 7, 12, 2 };
        var b = new[] { 2026, 7, 12, 1 };

        Assert.True(TemplateVersion.Compare(a, b) > 0);
    }

    [Fact]
    public void Compare_LowerFirst_ReturnsNegative()
    {
        var a = new[] { 2026, 7, 1, 1 };
        var b = new[] { 2026, 7, 12, 1 };

        Assert.True(TemplateVersion.Compare(a, b) < 0);
    }

    [Fact]
    public void Compare_Equal_ReturnsZero()
    {
        var a = new[] { 2026, 7, 12, 1 };
        var b = new[] { 2026, 7, 12, 1 };

        Assert.Equal(0, TemplateVersion.Compare(a, b));
    }

    [Fact]
    public void Compare_DifferingYear_ComparesCorrectly()
    {
        var a = new[] { 2025, 12, 31, 99 };
        var b = new[] { 2026, 1, 1, 1 };

        Assert.True(TemplateVersion.Compare(a, b) < 0);
    }
}
