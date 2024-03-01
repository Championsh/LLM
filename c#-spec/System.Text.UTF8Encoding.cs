using System;

namespace System.Text
{
    public class UTF8Encoding : Encoding
    {
        public virtual byte[] GetBytes(string s)
        {
            var b = new byte[s.Length];
            for (int i = 0; i < s.Length; i++)
                b[i] = (byte)s[i];
            return b;
        }

        public virtual string GetString(byte[] bytes)
        {
            var s = "";
            for (int i = 0; i < bytes.Length; i++)
                s += (char)bytes[i];
            return s;
        }
    }
}