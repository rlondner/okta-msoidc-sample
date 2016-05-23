using IdentityModel.Client;
using System;
using System.Configuration;
using System.Security.Claims;
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

        public ActionResult Claims()
        {
            ViewBag.Message = "Your claims.";

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
            if (form["error"] != null)
            { //we fall here when Okta is the Authorization server
                string error = form["error"];
                string desc = form["error_description"];
            }
            else if (form["code"] != null)
            {//we fall here when IdentityServer is the Authorization server
                string authCode = form["code"];
                string state = form["state"];

                //string oidcClientId = ConfigurationManager.AppSettings["OpenIDConnect_ClientId"];
                //string oidcClientSecret = ConfigurationManager.AppSettings["OpenIDConnect_ClientSecret"];
                //string oktaTenantUrl = ConfigurationManager.AppSettings["OpenIDConnect_Authority"];

                //var tokenClient = new TokenClient(
                //    oktaTenantUrl + "/oauth2/v1/token",
                //    oidcClientId,
                //    oidcClientSecret);

                //var tokenResponse = tokenClient.RequestAuthorizationCodeAsync(authCode, Request.UserHostAddress + "/Home/Claims");

                //if (tokenResponse.Is)
                //{
                //    throw new Exception(tokenResponse.Error);
                //}



                //return View((User as ClaimsPrincipal).Claims);

            }

            return View();
        }
    }
}