using System;
using System.Collections.Generic;
using NUnit.Framework;

namespace Whois.Tokens
{
    [TestFixture]
    public class TokenizerTest
    {
        private Tokenizer tokenizer;

        private class TestClass
        {
            public string Message { get; set; }

            public int Counter { get; set; }

            public IList<string> List { get; set; }

            public TestClass Nested { get; set; }
        }

        [SetUp]
        public void SetUp()
        {
            tokenizer = new Tokenizer();
        }

        [Test]
        public void TestGetTokenFromMiddleOfString()
        {
            const string pattern = "test #{TestClass.Message:ToUpper()} string";

            var token = tokenizer.GetNextToken(pattern);

            Assert.AreEqual("test ", token.Prefix);
            Assert.AreEqual("TestClass.Message", token.Value);
            Assert.AreEqual("ToUpper()", token.Operation);
            Assert.AreEqual(" string", token.Suffix);
        }

        [Test]
        public void TestGetTokenFromStartOfString()
        {
            const string pattern = "#{TestClass.Message} test string";

            var token = tokenizer.GetNextToken(pattern);

            Assert.AreEqual(string.Empty, token.Prefix);
            Assert.AreEqual("TestClass.Message", token.Value);
            Assert.AreEqual(" test string", token.Suffix);
        }

        [Test]
        public void TestGetTokenFromEndOfString()
        {
            const string pattern = " test string #{TestClass.Message}";

            var token = tokenizer.GetNextToken(pattern);

            Assert.AreEqual(" test string ", token.Prefix);
            Assert.AreEqual("TestClass.Message", token.Value);
            Assert.AreEqual(string.Empty, token.Suffix);
        }

        [Test]
        public void TestGetMulitipleTokens()
        {
            const string pattern = "begining #{TestClass.Message} middle #{TestClass.Counter} end";

            var token = tokenizer.GetTokens(pattern);

            Assert.AreEqual(2, token.Count);
            Assert.AreEqual("begining ", token[0].Prefix);
            Assert.AreEqual("TestClass.Message", token[0].Value);
            Assert.AreEqual(" middle ", token[0].Suffix);
            Assert.AreEqual(" middle ", token[1].Prefix);
            Assert.AreEqual("TestClass.Counter", token[1].Value);
            Assert.AreEqual(" end", token[1].Suffix);
        }

        [Test]
        public void TestGetMulitipleTokensWithMulitpleLines()
        {
            const string pattern = @"
begining #{TestClass.Message} 
middle #{TestClass.Counter} 
end #{TestClass.Nested.Counter}";

            var token = tokenizer.GetTokens(pattern);

            Assert.AreEqual(3, token.Count);
            Assert.AreEqual("\r\nbegining ", token[0].Prefix);
            Assert.AreEqual("TestClass.Message", token[0].Value);
            Assert.AreEqual(" \r\nmiddle ", token[0].Suffix);
            Assert.AreEqual(" \r\nmiddle ", token[1].Prefix);
            Assert.AreEqual("TestClass.Counter", token[1].Value);
            Assert.AreEqual(" \r\nend ", token[1].Suffix);
            Assert.AreEqual(" \r\nend ", token[2].Prefix);
            Assert.AreEqual("TestClass.Nested.Counter", token[2].Value);
            Assert.AreEqual("", token[2].Suffix);
        }

        [Test]
        public void TestExtractString()
        {
            const string input = "test hello world string";
            const string pattern = "test #{TestClass.Message} string";

            var result = tokenizer.Parse<TestClass>(pattern, input);

            Assert.AreEqual(1, result.Replacements.Count);
            Assert.AreEqual("TestClass.Message", result.Replacements[0].Value);
            Assert.AreEqual(typeof(TestClass), result.Value.GetType());
            Assert.AreEqual("hello world", result.Value.Message);
        }

        [Test]
        public void TestExtractInteger()
        {
            const string input = "test 1234 string";
            const string pattern = "test #{TestClass.Counter} string";

            var result = tokenizer.Parse<TestClass>(pattern, input);

            Assert.AreEqual(1234, result.Value.Counter);
        }

        [Test]
        public void TestExtractNestedValue()
        {
            const string input = "test 1234 string";
            const string pattern = "test #{TestClass.Nested.Counter} string";

            var result = tokenizer.Parse<TestClass>(pattern, input);

            Assert.AreEqual(1234, result.Value.Nested.Counter);
        }

        [Test]
        public void TestExtractMultipleStrings()
        {
            const string input = "test hello world string";
            const string pattern = "test #{TestClass.Message} string";

            var result = tokenizer.Parse<TestClass>(pattern, input);

            Assert.AreEqual("hello world", result.Value.Message);
        }

        [Test]
        public void TestSetValueString()
        {
            var result = tokenizer.SetValue(new TestClass(), "TestClass.Message", "It Worked");

            Assert.AreEqual("It Worked", result.Message);
        }

        [Test]
        public void TestSetValueInteger()
        {
            var result = tokenizer.SetValue(new TestClass(), "TestClass.Counter", 1234);

            Assert.AreEqual(1234, result.Counter);
        }

        [Test]
        public void TestSetValueWhenPathTooShort()
        {
            Assert.Throws<ArgumentException>(() => tokenizer.SetValue(new TestClass(), "TestClass", 1234));
        }

        [Test]
        public void TestSetValueWhenPathOfIncorrectBaseClassType()
        {
            Assert.Throws<ArgumentException>(() => tokenizer.SetValue(new TestClass(), "WrongTestClass.Message", 1234));
        }

        [Test]
        public void TestSetValueIntegerToString()
        {
            var result = tokenizer.SetValue(new TestClass(), "TestClass.Message", 1234);

            Assert.AreEqual("1234", result.Message);
        }

        [Test]
        public void TestSetValueStringToInteger()
        {
            var result = tokenizer.SetValue(new TestClass(), "TestClass.Counter", "1234");

            Assert.AreEqual(1234, result.Counter);
        }

        [Test]
        public void TestSetValuePreservesExistingValues()
        {
            var input = new TestClass { Message = "Existing Message" };

            var result = tokenizer.SetValue(input, "TestClass.Counter", "1234");

            Assert.AreEqual(input, result);
            Assert.AreEqual(1234, result.Counter);
            Assert.AreEqual("Existing Message", result.Message);
        }

        [Test]
        public void TestSetNestedValueString()
        {
            var result = tokenizer.SetValue(new TestClass(), "TestClass.Nested.Message", "Nested Hello");

            Assert.AreEqual("Nested Hello", result.Nested.Message);
        }

        [Test]
        public void TestSetListValueString()
        {
            var result = tokenizer.SetValue(new TestClass(), "TestClass.List", "First");

            Assert.AreEqual(1, result.List.Count);
            Assert.AreEqual("First", result.List[0]);
        }

        [Test]
        public void TestSetMultipleListValueString()
        {
            var testClass = new TestClass();

            tokenizer.SetValue(testClass, "TestClass.List", "First");
            tokenizer.SetValue(testClass, "TestClass.List", "Second");
            tokenizer.SetValue(testClass, "TestClass.List", "Third");

            Assert.AreEqual(3, testClass.List.Count);
            Assert.AreEqual("First", testClass.List[0]);
            Assert.AreEqual("Second", testClass.List[1]);
            Assert.AreEqual("Third", testClass.List[2]);
        }
        
        [Test]
        public void TestMultipleLinePatterns()
        {
            var pattern = "Hello #{TestClass.Message} World\r\nGoodbye #{TestClass.Counter} Everyone\r\n";
            var input = new[] { "Hello 'They Said It Here!' World", "Goodbye 123456 Everyone" };

            var result = tokenizer.Parse(new TestClass(), pattern, input);

            Assert.AreEqual(result.Value.Message, "'They Said It Here!'");
            Assert.AreEqual(result.Value.Counter, 123456);
        }
    }
}
