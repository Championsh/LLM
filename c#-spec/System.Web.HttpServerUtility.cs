using System.Web.UI.Adapters;
using System.Web.UI.HtmlControls;

namespace System.Web
{
    public sealed class HttpServerUtility
    {
        public string MapPath(string path)
        {
            return "someBasePath" + path;
        }
        public static string HtmlDecode(string s) => s;
        public static string HtmlEncode(string s) => s;
        public static string HtmlEncode(object s) => s.ToString();
        public static string UrlDecode(string s) => s;
        public static string UrlEncode(string s) => s;
        public static string UrlPathEncode(string s) => s;
    }
}