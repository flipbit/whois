using System;
using Flipbit.Core.Whois;

namespace Flipbit
{
    class Program
    {
        /// <summary>
        /// Simple program to do a WHOIS lookup then exit.
        /// </summary>
        /// <param name="args">The args.</param>
        static void Main(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                Console.WriteLine("Usage: whois [domain]");
            }
            else
            {
                var result = new WhoisLookup().Lookup(args[0]);

                Console.WriteLine(result.ToString());
                Console.WriteLine("");
                Console.WriteLine("Domain Created: {0:dd-MM-yyyy}", result.Created);
            }
        }
    }
}