using System;

namespace System.Text
{
    public class Encoding
    {
        public virtual byte[] GetBytes(string s) => CSharpCodeChecker_Kostil.AnyConverter.Convert<string, byte[]>(s);
        public virtual string GetString(byte[] bytes) => CSharpCodeChecker_Kostil.AnyConverter.Convert<byte[], string>(bytes);
    }
}