using System.Collections;
using System.Text;
using Whois.Interfaces;

namespace Whois.Visitors
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisVisitor : IWhoisVisitor
    {
        private readonly string fakeContent;

        public Encoding Encoding { get; private set; }

        public FakeWhoisVisitor(string content)
        {
            fakeContent = content;
        }

        public WhoisRecord Visit(WhoisRecord record)
        {
            record.Text =  fakeContent;

            return record;
        }
    }
}
