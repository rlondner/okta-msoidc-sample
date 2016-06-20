using Newtonsoft.Json.Linq;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace OktaOpenIDConnect.Controllers
{
    public class CallApiController : Controller
    {
        // GET: CallApi
        public ActionResult Index()
        {
            return View();
        }

        // GET: CallApi/ClientCredentials
        public async Task<ActionResult> ClientCredentials()
        {
            ClaimsPrincipal identity = Request.GetOwinContext().Authentication.User;

            var name = identity.Claims.Where(c => c.Type == ClaimTypes.Name)
                   .Select(c => c.Value).SingleOrDefault();

            var accessToken = identity.Claims.Where(c => c.Type == "access_token").Select(c => c.Value).SingleOrDefault();

            var idToken = identity.Claims.Where(c => c.Type == "id_token")
.Select(c => c.Value).SingleOrDefault();

            var result = await CallApi(accessToken);

            //var result = await CallApi(idToken);

            ViewBag.Json = result;
            return View("ShowApiResult");
        }


        //private async Task<TokenResponse> GetTokenAsync()
        //{
        //    var client = new TokenClient(
        //        "https://localhost:44323/identity/connect/token",
        //        "mvc_service",
        //        "secret");

        //    return await client.RequestClientCredentialsAsync("sampleApi");
        //}

        private async Task<string> CallApi(string token)
        {
            
            var client = new HttpClient();
            client.SetBearerToken(token);

            var json = await client.GetStringAsync("https://localhost:44316/identity");
            return JArray.Parse(json).ToString();
        }
    }
}