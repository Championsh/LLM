using System;
using System.Text;
using System.Web;

namespace System.Net
{
    public sealed class WebUtility
    {
        public static string HtmlDecode(string s) => s;
        public static string HtmlEncode(string s) => s;
        public static string UrlDecode(string s) => s;
        public static string UrlEncode(string s) => s;
    }
}