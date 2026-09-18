using System.Xml.Linq;
using Xunit;

namespace Whois;

public class ProjectDependencyTests
{
    private static readonly string ProjectFilePath = Path.Combine(
        GetRepositoryRoot(),
        "src", "Whois", "Whois.csproj");

    /// <summary>
    /// The core library must only depend on abstractions packages, not full implementations.
    /// Dependabot PRs have repeatedly tried to add the implementation packages as direct
    /// dependencies (e.g. Microsoft.Extensions.Configuration, Microsoft.Extensions.DependencyInjection,
    /// Microsoft.Extensions.Logging). These belong in test/console projects, not the library itself.
    /// </summary>
    [Theory]
    [InlineData("Microsoft.Extensions.Configuration")]
    [InlineData("Microsoft.Extensions.DependencyInjection")]
    [InlineData("Microsoft.Extensions.Logging")]
    [InlineData("Microsoft.Extensions.Logging.Console")]
    public void CoreLibrary_ShouldNotReference_ImplementationPackages(string packageName)
    {
        var doc = XDocument.Load(ProjectFilePath);
        var references = doc.Descendants("PackageReference")
            .Select(e => e.Attribute("Include")?.Value)
            .Where(v => v is not null)
            .ToList();

        Assert.DoesNotContain(packageName, references, StringComparer.OrdinalIgnoreCase);
    }

    private static string GetRepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);

        while (dir is not null)
        {
            if (dir.GetFiles(".gitignore").Length > 0)
                return dir.FullName;

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not find repository root");
    }
}
