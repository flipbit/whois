using System.Collections;
using NUnit.Framework;

namespace Flipbit.Core.Whois.Arrays
{
    [TestFixture]
    public class EndsWithExtensionTest
    {
        [Test]
        public void TestFindFirstLine()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.EndsWith("first");

            Assert.AreEqual("line first", result);
        }

        [Test]
        public void TestFindSecondLine()
        {
            var array = new ArrayList { "line first", "line second", "line third" };

            var result = array.EndsWith("second");

            Assert.AreEqual("line second", result);
        }

        [Test]
        public void TestFindThirdLineNotFound()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.EndsWith("third");

            Assert.AreEqual(string.Empty, result);
        }

        [Test]
        public void TestFindFirstLinesIndex()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineEndingWith("first");

            Assert.AreEqual(0, result);
        }

        [Test]
        public void TestFindFirstLineFromIndex()
        {
            var array = new ArrayList { "line first", "second line", "first but third line first" };

            var result = array.EndsWith("first", 1);

            Assert.AreEqual("first but third line first", result);
        }

        [Test]
        public void TestFindSecondLinesIndex()
        {
            var array = new ArrayList { "line first", "line second", "line third" };

            var result = array.IndexOfLineEndingWith("second");

            Assert.AreEqual(1, result);
        }


        [Test]
        public void TestFindThirdLinesIndexNotFound()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineEndingWith("third");

            Assert.AreEqual(-1, result);
        }

        [Test]
        public void TestFindFirstLinesIndexAfterIndex()
        {
            var array = new ArrayList { "line first", "line second", "line second first" };

            var result = array.IndexOfLineEndingWith("first", 1);

            Assert.AreEqual(2, result);
        }

        [Test]
        public void TestFindSecondLinesIndexAfterIndex()
        {
            var array = new ArrayList { "line first", "line second", "line third" };

            var result = array.IndexOfLineEndingWith("second", 1);

            Assert.AreEqual(1, result);
        }


        [Test]
        public void TestFindThirdLinesIndexNotFoundAfterIndex()
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineEndingWith("third", 3);

            Assert.AreEqual(-1, result);
        }
    }
}