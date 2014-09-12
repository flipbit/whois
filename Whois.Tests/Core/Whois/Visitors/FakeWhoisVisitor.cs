using System.Collections;
using System.Text;
using Flipbit.Core.Whois.Domain;
using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois.Visitors
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisVisitor : IWhoisVisitor
    {
        private readonly string fakeContent;

        public Encoding CurrentEncoding { get; private set; }

        public FakeWhoisVisitor(string content)
        {
            fakeContent = content;
        }

        public WhoisRecord Visit(WhoisRecord record)
        {
            record.Text = new ArrayList { fakeContent };

            return record;
        }
    }
}
