using System;

namespace Whois.Net
{
    public static class TcpReaderFactory
    {
        private static Func<ITcpReader> factoryFunc;

        static TcpReaderFactory()
        {
            factoryFunc = () => new TcpReader();
        }

        public static ITcpReader Create()
        {
            return factoryFunc.Invoke();
        }

        public static void Bind(Func<ITcpReader> factory)
        {
            factoryFunc = factory;
        }
    }
}
