using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Educause.Edu.Edu
{
    [TestFixture]
    public class EduParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_fixture2()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture2.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_fixture3()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture3.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_fixture4()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture4.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_fixture5()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture5.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_fixture6()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_fixture6.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contacts()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contacts_case1()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts_case1.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contacts_case2()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts_case2.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contacts_case3()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts_case3.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contacts_case4()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contacts_case4.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_registrant()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contact_registrant.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_registrant_without_address()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contact_registrant_without_address.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_registrant_without_zip()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contact_registrant_without_zip.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_registrant_with_additional_organization()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_contact_registrant_with_additional_organization.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_updated_on_unknown()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_updated_on_unknown.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "not_found.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.educause.edu", "edu", "found_status_registered.txt");
            var response = parser.Parse("whois.educause.edu", "edu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
