using System.Collections;
using NUnit.Framework;

namespace Flipbit.Core.Whois.Arrays
{
    [TestFixture]
    public class StartsWithExtensionTest
    {
        [Test]
        public void TestFindFirstLine()
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.StartsWith("first");

            Assert.AreEqual("first line", result);
        }

        [Test]
        public void TestFindSecondLine()
        {
            var array = new ArrayList { "first line", "second line", "third line" };

            var result = array.StartsWith("second");

            Assert.AreEqual("second line", result);
        }

        [Test]
        public void TestFindThirdLineNotFound()
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.StartsWith("third");

            Assert.AreEqual(string.Empty, result);
        }

        [Test]
        public void TestFindFirstLineFromIndex()
        {
            var array = new ArrayList { "first line", "second line", "first but third line" };

            var result = array.StartsWith("first", 1);

            Assert.AreEqual("first but third line", result);
        }

        [Test]
        public void TestFindFirstLinesIndex()
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.IndexOfLineStartingWith("first");

            Assert.AreEqual(0, result);
        }

        [Test]
        public void TestFindSecondLinesIndex()
        {
            var array = new ArrayList { "first line", "second line", "third line" };

            var result = array.IndexOfLineStartingWith("second");

            Assert.AreEqual(1, result);
        }


        [Test]
        public void TestFindThirdLinesIndexNotFound()
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.IndexOfLineStartingWith("third");

            Assert.AreEqual(-1, result);
        }

        [Test]
        public void TestFindFirstLinesIndexAfterIndex()
        {
            var array = new ArrayList { "first line", "second line", "first line again" };

            var result = array.IndexOfLineStartingWith("first", 1);

            Assert.AreEqual(2, result);
        }

        [Test]
        public void TestFindSecondLinesIndexAfterIndex()
        {
            var array = new ArrayList { "first line", "second line", "third line" };

            var result = array.IndexOfLineStartingWith("second", 1);

            Assert.AreEqual(1, result);
        }


        [Test]
        public void TestFindThirdLinesIndexNotFoundAfterIndex()
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.IndexOfLineStartingWith("third", 3);

            Assert.AreEqual(-1, result);
        }
    }
}