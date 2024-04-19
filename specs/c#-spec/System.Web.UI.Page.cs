using System.Web.UI.Adapters;
using System.Web.UI.HtmlControls;

namespace System.Web.UI
{
    public class Page : TemplateControl, IHttpHandler
    {
        public bool IsReusable => throw new NotImplementedException();

        public string MapPath(string virtualPath)
        {
            return "someBasePath" + virtualPath;
        }

        public void ProcessRequest(HttpContext context)
        {
            throw new NotImplementedException();
        }
    }
}