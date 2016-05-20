using System;
using System.Web.Mvc;

namespace OktaOpenIDConnect.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        [Authorize]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        [HttpPost]
        public ActionResult OpenIDConnect(FormCollection form)
        {
            if(form["error"] != null)
            { //we fall here when Okta is the Authorization server
                string error = form["error"];
                string desc = form["error_description"];
            }
            else if(form["code"] != null) 
            {//we fall here when IdentityServer is the Authorization server
                string authCode = form["code"];
                string state = form["state"];
                string sessionState = form["session_state"];
            }

            return View();
        }
    }
}