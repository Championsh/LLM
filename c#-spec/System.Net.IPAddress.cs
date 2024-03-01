using System;
namespace System.Net
{
    public class IPAddress
    {
        public static IPAddress Parse(string ipString)
            => CSharpCodeChecker_Kostil.AnyConverter.Convert<string, IPAddress>(ipString);
    }
}