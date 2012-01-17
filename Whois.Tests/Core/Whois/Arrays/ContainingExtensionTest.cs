using System.Collections;
using NUnit.Framework;

namespace Flipbit.Core.Whois.Arrays
{
    [TestFixture]
    public class ContainingExtensionTest
    {
        [Test]
        public void TestFindFirstLine()
        {
            var array = new ArrayList { "line first after", "line second after" };

            var result = array.Containing("first");

            Assert.AreEqual("line first after", result);
        }

        [Test]
        public void TestFindSecondLine()
        {
            var array = new ArrayList { "line first", "line second after", "line third" };

            var result = array.Containing("second");

            Assert.AreEqual("line second after", result);
        }

        [Test]
        public void TestFindThirdLineNotFound()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.Containing("third");

            Assert.AreEqual(string.Empty, result);
        }


        [Test]
        public void TestFindFirstLineFromIndex()
        {
            var array = new ArrayList { "line first data", "line second data", "line first but third data" };

            var result = array.Containing("first", 1);

            Assert.AreEqual("line first but third data", result);
        }

        [Test]
        public void TestFindFirstLinesIndex()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineContaining("first");

            Assert.AreEqual(0, result);
        }

        [Test]
        public void TestFindSecondLinesIndex()
        {
            var array = new ArrayList { "line first", "line second", "line third" };

            var result = array.IndexOfLineContaining("second");

            Assert.AreEqual(1, result);
        }


        [Test]
        public void TestFindThirdLinesIndexNotFound()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineContaining("third");

            Assert.AreEqual(-1, result);
        }

        [Test]
        public void TestFindFirstLinesIndexAfterIndex()
        {
            var array = new ArrayList { "line first", "line second", "line second first" };

            var result = array.IndexOfLineContaining("first", 1);

            Assert.AreEqual(2, result);
        }

        [Test]
        public void TestFindSecondLinesIndexAfterIndex()
        {
            var array = new ArrayList { "line first", "line second", "line third" };

            var result = array.IndexOfLineContaining("second", 1);

            Assert.AreEqual(1, result);
        }


        [Test]
        public void TestFindThirdLinesIndexNotFoundAfterIndex()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineContaining("third", 3);

            Assert.AreEqual(-1, result);
        }
    }
}