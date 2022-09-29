using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Whois
{
    public static class LogProvider
    {
        public static ILoggerFactory Factory = new NullLoggerFactory();
        public static ILogger<T> For<T>()
        {
            return Factory.CreateLogger<T>();
        }
    }
}