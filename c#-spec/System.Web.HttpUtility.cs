using System;
using System.Text;
using System.Web;

namespace System.Web
{
    public sealed class HttpUtility
    {
        public static string HtmlAttributeEncode(string s) => s;
        public static string HtmlDecode(string s) => s;
        public static string HtmlEncode(string s) => s;
        public static string HtmlEncode(object s) => s.ToString();
        public static string JavaScriptStringEncode(string s) => s;
        public static string JavaScriptStringEncode(string s, bool b) => s;
        // ParseQueryString(string)
        // ParseQueryString(string, Encoding)
        // UrlDecode(byte[], Encoding)
        // UrlDecode(byte[], int, int, Encoding)
        public static string UrlDecode(string s) => s;
        public static string UrlDecode(string s, Encoding e) => s;
        public static string UrlEncode(string s) => s;
        public static string UrlEncode(string s, Encoding e) => s;
        public static string UrlEncodeUnicode(string s) => s;
        public static string UrlPathEncode(string s) => s;
        // UrlEncodeToBytes
        //...
        
    }
}