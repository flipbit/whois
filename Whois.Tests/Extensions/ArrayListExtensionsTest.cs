using System.Collections;
using NUnit.Framework;

namespace Whois.Extensions
{
    [TestFixture]
    public class ArrayListExtensionsTest
    {
        [Test]
        public void TestEmptyListAsString()
        {
            var array = new ArrayList();

            Assert.AreEqual(string.Empty, array.AsString());
        }

        [Test]
        public void TestNonEmptyListAsString()
        {
            var array = new ArrayList { "First", "Second", "Third" };

            Assert.AreEqual("First\r\nSecond\r\nThird\r\n", array.AsString());
        }

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

        [Test]
        public void TestFindEndsWithFirstLine() 
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.EndsWith("first");

            Assert.AreEqual("line first", result);
        }

        [Test]
        public void TestFindEndsWithSecondLine() 
        {
            var array = new ArrayList { "line first", "line second", "line third" };

            var result = array.EndsWith("second");

            Assert.AreEqual("line second", result);
        }

        [Test]
        public void TestFindEndsWithThirdLineNotFound() 
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.EndsWith("third");

            Assert.AreEqual(string.Empty, result);
        }

        [Test]
        public void TestFindEndsWithFirstLinesIndex() 
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineEndingWith("first");

            Assert.AreEqual(0, result);
        }

        [Test]
        public void TestFindEndsWithFirstLineFromIndex() 
        {
            var array = new ArrayList { "line first", "second line", "first but third line first" };

            var result = array.EndsWith("first", 1);

            Assert.AreEqual("first but third line first", result);
        }

        [Test]
        public void TestFindEndsWithSecondLinesIndex() 
        {
            var array = new ArrayList { "line first", "line second", "line third" };

            var result = array.IndexOfLineEndingWith("second");

            Assert.AreEqual(1, result);
        }


        [Test]
        public void TestFindEndsWithThirdLinesIndexNotFound() 
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineEndingWith("third");

            Assert.AreEqual(-1, result);
        }

        [Test]
        public void TestFindEndsWithFirstLinesIndexAfterIndex() 
        {
            var array = new ArrayList { "line first", "line second", "line second first" };

            var result = array.IndexOfLineEndingWith("first", 1);

            Assert.AreEqual(2, result);
        }

        [Test]
        public void TestFindEndsWithSecondLinesIndexAfterIndex() 
        {
            var array = new ArrayList { "line first", "line second", "line third" };

            var result = array.IndexOfLineEndingWith("second", 1);

            Assert.AreEqual(1, result);
        }

        [Test]
        public void TestFindEndsWithThirdLinesIndexNotFoundAfterIndex() 
        {
            var array = new ArrayList { "line first", "line second" };

            var result = array.IndexOfLineEndingWith("third", 3);

            Assert.AreEqual(-1, result);
        }

        [Test]
        public void TestFindStartsWithFirstLine() 
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.StartsWith("first");

            Assert.AreEqual("first line", result);
        }

        [Test]
        public void TestFindStartsWithSecondLine() 
        {
            var array = new ArrayList { "first line", "second line", "third line" };

            var result = array.StartsWith("second");

            Assert.AreEqual("second line", result);
        }

        [Test]
        public void TestFindStartsWithThirdLineNotFound() 
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.StartsWith("third");

            Assert.AreEqual(string.Empty, result);
        }

        [Test]
        public void TestFindStartsWithFirstLineFromIndex() 
        {
            var array = new ArrayList { "first line", "second line", "first but third line" };

            var result = array.StartsWith("first", 1);

            Assert.AreEqual("first but third line", result);
        }

        [Test]
        public void TestFindStartsWithFirstLinesIndex() 
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.IndexOfLineStartingWith("first");

            Assert.AreEqual(0, result);
        }

        [Test]
        public void TestFindStartsWithSecondLinesIndex() 
        {
            var array = new ArrayList { "first line", "second line", "third line" };

            var result = array.IndexOfLineStartingWith("second");

            Assert.AreEqual(1, result);
        }

        [Test]
        public void TestFindStartsWithThirdLinesIndexNotFound() 
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.IndexOfLineStartingWith("third");

            Assert.AreEqual(-1, result);
        }

        [Test]
        public void TestFindStartsWithFirstLinesIndexAfterIndex() 
        {
            var array = new ArrayList { "first line", "second line", "first line again" };

            var result = array.IndexOfLineStartingWith("first", 1);

            Assert.AreEqual(2, result);
        }

        [Test]
        public void TestFindStartsWithSecondLinesIndexAfterIndex() 
        {
            var array = new ArrayList { "first line", "second line", "third line" };

            var result = array.IndexOfLineStartingWith("second", 1);

            Assert.AreEqual(1, result);
        }

        [Test]
        public void TestFindStartsWithThirdLinesIndexNotFoundAfterIndex() 
        {
            var array = new ArrayList { "first line", "second line" };

            var result = array.IndexOfLineStartingWith("third", 3);

            Assert.AreEqual(-1, result);
        }
    }
}
