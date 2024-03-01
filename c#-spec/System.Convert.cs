using System;
namespace System
{
    public class Convert
    {
        public static int ToInt32(string value)
            => CSharpCodeChecker_Kostil.AnyConverter.Convert<string, int>(value);

        public static byte[] FromBase64String(string value)
            => CSharpCodeChecker_Kostil.AnyConverter.Convert<string, byte[]>(value);
    }
}
