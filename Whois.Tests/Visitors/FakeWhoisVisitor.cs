using System.Text;
using System.Threading.Tasks;
using Whois.Models;

namespace Whois.Visitors
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisVisitor : IWhoisVisitor
    {
        private readonly string fakeContent;

        public FakeWhoisVisitor(string content)
        {
            fakeContent = content;
        }

        public Task<LookupState> Visit(LookupState record)
        {
            record.Response = new WhoisResponse(fakeContent);

            return Task.FromResult(record);
        }
    }
}
