using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Globalization;

namespace System
{
    public class String
    {
        public static string Empty => "";
        private int _length; // TODO: model length change

        public int Length => _length;

        public static implicit operator string(System.String s) => (string) ((object) s);

        public static implicit operator System.String(string s) => (string) ((object) s);

        public override string ToString() => this;

        public static string Join(string separator, params string[] value)
        {
            return value[0] + separator;
        }

        public static string Join(string separator, params object[] values)
        {
            return values[0].ToString() + separator;
        }

        public static string Join(string separator, string[] value, int startIndex, int count)
        {
            string x = "";
            for (int i = startIndex; i < startIndex + count; ++i)
                x += value[i] + separator;
            return x;
        }

        public static string Join<T>(string separator, IEnumerable<T> values)
        {
            string x = "";
            foreach (T v in values)
                x += v.ToString() + separator;
            return x;
        }

        public static string Join(string separator, IEnumerable<string> values)
        {
            string x = "";
            foreach (string v in values)
                x += v + separator;
            return x;
        }

        public static string Format(string format, object arg0)
        {
            return format + arg0?.ToString();
        }

        public static string Format(string format, object arg0, object arg1)
        {
            return format + arg0?.ToString() + arg1?.ToString();
        }

        public static string Format(string format, object arg0, object arg1, object arg2)
        {
            return format + arg0?.ToString() + arg1?.ToString() + arg2?.ToString();
        }

        public static string Format(string format, params object[] args)
        {
            return format + args[0]; // really dereferences args array
        }

        public static string Format(IFormatProvider provider, string format, object arg0)
        {
            return format + arg0?.ToString();
        }

        public static string Format(IFormatProvider provider, string format, object arg0, object arg1)
        {
            return format + arg0?.ToString() + arg1?.ToString();
        }

        public static string Format(IFormatProvider provider, string format, object arg0, object arg1, object arg2)
        {
            return format + arg0?.ToString() + arg1?.ToString() + arg2?.ToString();
        }

        public static string Format(IFormatProvider provider, string format, params object[] args)
        {
            return format + args[0]; // really dereferences args array
        }

        public string Trim(params char[] trimChars) => this;

        public string TrimStart(params char[] trimChars) => this;

        public string TrimEnd(params char[] trimChars) => this;

        public string Normalize() => this;

        public string Normalize(NormalizationForm normalizationForm) => this;

        public string PadLeft(int totalWidth) => this;

        public string PadLeft(int totalWidth, char paddingChar) => this;

        public string PadRight(int totalWidth) => this;

        public string PadRight(int totalWidth, char paddingChar) => this;

        public string ToLower() => this;

        public string ToLower(CultureInfo culture) => this;

        public string ToLowerInvariant() => this;

        public string ToUpper() => this;

        public string ToUpper(CultureInfo culture) => this;

        public string ToUpperInvariant() => this;

        public string ToString(IFormatProvider provider) => this;

        public object Clone() => this;

        public string Trim() => this;

        public string Insert(int startIndex, string value) => this + value;

        public string Replace(char oldChar, char newChar) => this;

        public string Replace(string oldValue, string newValue) => this + newValue;

        public string Remove(int startIndex, int count) => this;

        public string Remove(int startIndex) => this;

        public static string Intern(string str) => str;

        public static string Copy(string str) => str;

        public string Substring(int startIndex, int length) => this;

        public string Substring(int startIndex) => this;

        public string[] Split(params char[] separator) => new string[] {this};

        public string[] Split(char[] separator, int count) => new string[] {this};

        public string[] Split(char[] separator, StringSplitOptions options) => new string[] {this};

        public string[] Split(char[] separator, int count, StringSplitOptions options) => new string[] {this};

        public string[] Split(string[] separator, StringSplitOptions options) => new string[] {this};

        public string[] Split(string[] separator, int count, StringSplitOptions options) => new string[] {this};

        public static string Concat(object arg0) => arg0.ToString();

        public static string Concat(object arg0, object arg1) => arg0.ToString() + arg1.ToString();

        public static string Concat(object arg0, object arg1, object arg2) =>
            arg0.ToString() + arg1.ToString() + arg2.ToString();

        public static string Concat(object arg0, object arg1, object arg2, object arg3, __arglist) =>
            arg0.ToString() + arg1.ToString() + arg2.ToString() + arg3.ToString(); // We won't support __arglist

        public static string Concat(params object[] args) => args[0].ToString();

        public static string Concat<T>(IEnumerable<T> values)
        {
            string x = "";
            foreach (T v in values)
                x += v.ToString();
            return x;
        }

        public static string Concat(IEnumerable<string> values)
        {
            string x = "";
            foreach (string v in values)
                x += v;
            return x;
        }

        public static string Concat(string str0, string str1) => str0 + str1;

        public static string Concat(string str0, string str1, string str2) => str0 + str1 + str2;

        public static string Concat(string str0, string str1, string str2, string str3) => str0 + str1 + str2 + str3;

        public static string Concat(params string[] values) => values[0];
    }
}
