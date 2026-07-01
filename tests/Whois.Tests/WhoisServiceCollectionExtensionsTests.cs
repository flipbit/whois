using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Whois.Net;
using Whois.Servers;
using Xunit;

namespace Whois
{
    public class WhoisServiceCollectionExtensionsTests
    {
        [Fact]
        public void AddWhois_RegistersServices()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddWhois();
            var provider = services.BuildServiceProvider();

            Assert.NotNull(provider.GetService<IWhoisLookup>());
            Assert.NotNull(provider.GetService<ITcpReader>());
            Assert.NotNull(provider.GetService<IWhoisServerLookup>());
        }

        [Fact]
        public void AddWhois_WithConfigure_SetsOptions()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddWhois(options =>
            {
                options.TimeoutSeconds = 30;
                options.FollowReferrer = false;
            });
            var provider = services.BuildServiceProvider();

            var options = provider.GetRequiredService<IOptions<WhoisOptions>>();
            Assert.Equal(30, options.Value.TimeoutSeconds);
            Assert.False(options.Value.FollowReferrer);
        }
    }
}
