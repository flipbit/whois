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
