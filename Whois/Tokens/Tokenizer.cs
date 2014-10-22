using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Lifetime;
using Whois.Extensions;

namespace Whois.Tokens
{
    /// <summary>
    /// Class that creates objects and populates their properties with values
    /// from input strings
    /// </summary>
    public class Tokenizer
    {
        /// <summary>
        /// Parses the given input and creates an object with values matching the specified pattern.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="pattern">The pattern.</param>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public TokenResult<T> Parse<T>(string pattern, string input) where T : class, new()
        {
            var result = new T();

            return Parse(result, pattern, input);
        }

        /// <summary>
        /// Parses the given input and creates an object with values matching the specified pattern.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="target">The target.</param>
        /// <param name="pattern">The pattern.</param>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public TokenResult<T> Parse<T>(T target, string pattern, string input) where T : class
        {
            var result = new TokenResult<T>(target);

            return Parse(result, pattern, input);
        }

        public TokenResult<T> Parse<T>(TokenResult<T> result, string pattern, string input) where T : class
        {
            // Extract all the tokens from the pattern
            var tokens = GetTokens(pattern);

            foreach (var token in tokens)
            {
                // Ignore tokens that aren't contained in the input
                if (!token.ContainedIn(input)) continue;

                // Extract token value from the input text
                var value = input.SubstringAfterChar(token.Prefix).SubstringBeforeChar(token.Suffix);

                // Perform token operation
                value = token.PerformOperation(value);

                // Use reflection to set the property on the object with the token value
                result.Value = SetValue(result.Value, token.Value, value);

                // Add the match to the result collection
                result.Replacements.Add(token);
            }

            return result;            
        }


        public TokenResult<T> Parse<T>(string pattern, IEnumerable<string> input) where T : class, new()
        {
            var target = new T();

            return Parse(target, pattern, input);
        }

        public TokenResult<T> Parse<T>(T target, string pattern, IEnumerable<string> input) where T : class
        {
            var result = new TokenResult<T>(target);

            var patternLines = pattern.Split('\n');

            foreach (var line in input)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                foreach (var patternLine in patternLines)
                {
                    result = Parse(result, patternLine.Trim(), line.Trim());
                }
            }

            return result;
        }

        /// <summary>
        /// Gets the next token that appears in the given pattern.
        /// </summary>
        /// <param name="pattern">The pattern.</param>
        /// <returns></returns>
        public Token GetNextToken(string pattern)
        {
            var token = new Token();

            token.Prefix = pattern.SubstringBeforeChar("#{");
            token.Suffix = pattern.SubstringAfterChar("}").SubstringBeforeChar("#{");
            token.Value = pattern.SubstringBeforeChar("}").SubstringAfterChar("#{");

            if (token.Value.Contains(":"))
            {
                token.Operation = token.Value.SubstringAfterChar(":");
                token.Value = token.Value.SubstringBeforeChar(":");
            }

            return token;
        }

        /// <summary>
        /// Gets the tokens present in the given pattern.
        /// </summary>
        /// <param name="pattern">The pattern.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public IList<Token> GetTokens(string pattern)
        {
            var results = new List<Token>();

            while (pattern.Contains("#{"))
            {
                var token = GetNextToken(pattern);

                results.Add(token);

                pattern = pattern.SubstringAfterChar("}");
            }

            return results;
        }

        /// <summary>
        /// Sets the given value on the given propetrty with the given path.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="object">The object.</param>
        /// <param name="propertyPath">The property path.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentException">Property Path Too Short:  + propertyPath</exception>
        public T SetValue<T>(T @object, string propertyPath, object value) where T : class
        {
            var segments = propertyPath.Split('.');
            var objectType = @object.GetType().Name;

            // Must have at least a single property (e.g. "Object.Property")
            if (segments.Length < 2) throw new ArgumentException("Property Path Too Short: " + propertyPath);

            // Check object type
            if (objectType != segments[0]) throw new ArgumentException(string.Format("Invalid Property Path for {0}: {1}", objectType, propertyPath));

            @object = SetInnerValue(@object, segments.Skip(1).ToArray(), value) as T;

            return @object;
        }

        private object SetInnerValue(object @object, string[] path, object value)
        {
            var propertyInfos = @object.GetType().GetProperties();

            foreach (var propertyInfo in propertyInfos)
            {
                if (propertyInfo.Name != path[0]) continue;

                if (path.Length == 1)
                {
                    if (propertyInfo.PropertyType.IsGenericType && propertyInfo.PropertyType.GetGenericTypeDefinition() == typeof(IList<>))
                    {
                        var list = propertyInfo.GetValue(@object, null); 

                        if (list == null)
                        {
                            var genericType = propertyInfo.PropertyType.GetGenericArguments()[0];
                            var enumerableType = typeof (List<>);
                            var constructedEnumerableType = enumerableType.MakeGenericType(genericType);
                            list = Activator.CreateInstance(constructedEnumerableType);

                            propertyInfo.SetValue(@object, list, null);
                        }

                        list.GetType().GetMethod("Add").Invoke(list, new[] { value });
                    }
                    else
                    {
                        var convertedValue = Convert.ChangeType(value, propertyInfo.PropertyType);

                        propertyInfo.SetValue(@object, convertedValue, null);
                    }

                    break;
                }

                var currentValue = propertyInfo.GetValue(@object, null);

                if (currentValue == null)
                {
                    currentValue = Activator.CreateInstance(propertyInfo.PropertyType);

                    propertyInfo.SetValue(@object, currentValue, null);
                }

                SetInnerValue(currentValue, path.Skip(1).ToArray(), value);

                break;
            }

            return @object;
        }
    }
}
