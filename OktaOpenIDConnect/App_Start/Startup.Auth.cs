using Microsoft.Owin.Diagnostics;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System.Configuration;

namespace OktaOpenIDConnect
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseErrorPage(new ErrorPageOptions
            {
                ShowCookies = true,
                ShowEnvironment = true,
                ShowQuery = true,
                ShowExceptionDetails = true,
                ShowHeaders = true,
                ShowSourceCode = true,
                SourceCodeLineCount = 10
            });

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            string oidcClientId = ConfigurationManager.AppSettings["OpenIDConnect_ClientId"] as string;
            string oidcAuthority = ConfigurationManager.AppSettings["OpenIDConnect_Authority"] as string;
            string oidcRedirectUri = ConfigurationManager.AppSettings["OpenIDConnect_RedirectUri"] as string;
            string oidcResponseType = ConfigurationManager.AppSettings["OpenIDConnect_ResponseType"] as string;

            //var oidcOptions = new OpenIdConnectAuthenticationOptions();
            
            //app.CreateDataProtector(
            //        typeof(OpenIdConnectAuthenticationMiddleware).FullName,
            //        CookieAuthenticationDefaults.AuthenticationType, "v1");

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = oidcClientId,
                Authority = oidcAuthority,
                RedirectUri = oidcRedirectUri,
                ResponseType = oidcResponseType,
                
            });
        }
    }
}
