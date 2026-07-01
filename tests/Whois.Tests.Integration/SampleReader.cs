using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Whois.Models;

namespace Whois
{
    internal class SampleReader
    {
        public List<SampleDomain> ReadSampleDomains()
        {
            var json = File.ReadAllText(Path.Join("..\\..\\..\\Samples", "Domains.txt"));

            return JsonConvert.DeserializeObject<List<SampleDomain>>(json);
        }
    }
}
