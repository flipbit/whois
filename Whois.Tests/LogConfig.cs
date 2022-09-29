using Microsoft.Extensions.Logging;

namespace Whois
{
    class LogConfig
    {
        public static void Init()
        {            
            // LoggerFactory should be disposed with the test case.
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Trace);
                builder.AddConsole(options => options.DisableColors = true);
            });
            LogProvider.Factory = loggerFactory;
        }
    }
}
