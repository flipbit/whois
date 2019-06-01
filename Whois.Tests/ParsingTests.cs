using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Resources;
using NUnit.Framework;
using Tokens;
using Whois.Models;
using Whois.Visitors;

namespace Whois
{
    public abstract class ParsingTests
    {
        protected ParsingTests()
        {
            SampleReader = new SampleReader();
        }

        protected SampleReader SampleReader { get; }
    }
}
