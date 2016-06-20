using Microsoft.Owin.Diagnostics;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System.Configuration;
using IdentityModel.Client;
using System;
using System.Security.Claims;


namespace Okta.Samples.OpenIDConnect.CodeFlow
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            //app.UseErrorPage(new ErrorPageOptions
            //{
            //    ShowCookies = true,
            //    ShowEnvironment = true,
            //    ShowQuery = true,
            //    ShowExceptionDetails = true,
            //    ShowHeaders = true,
            //    ShowSourceCode = true,
            //    SourceCodeLineCount = 10
            //});

            //app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            string oidcClientId = ConfigurationManager.AppSettings["OpenIDConnect_ClientId"] as string;
            string oidcClientSecret = ConfigurationManager.AppSettings["OpenIDConnect_ClientSecret"];
            string oidcAuthority = ConfigurationManager.AppSettings["OpenIDConnect_Authority"] as string;
            string oidcRedirectUri = ConfigurationManager.AppSettings["OpenIDConnect_RedirectUri"] as string;
            string oidcResponseType = ConfigurationManager.AppSettings["OpenIDConnect_ResponseType"] as string;


            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = oidcClientId,
                Authority = oidcAuthority,
                RedirectUri = oidcRedirectUri,
                ResponseType = oidcResponseType,
                Scope = "openid profile offline_access",

                SignInAsAuthenticationType = "Cookies",
                UseTokenLifetime = false,

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async n =>
                    {
                        // use the code to get the access and refresh token
                        var tokenClient = new TokenClient(
                            oidcAuthority + Constants.TokenEndpoint,
                            oidcClientId,
                            oidcClientSecret, AuthenticationStyle.PostValues);

                        //var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
                        //    n.Code, n.RedirectUri);

                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
    n.Code, n.RedirectUri);


                        if (tokenResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        // use the access token to retrieve claims from userinfo
                        var userInfoClient = new UserInfoClient(new Uri(oidcAuthority + Constants.UserInfoEndpoint), tokenResponse.AccessToken);

                        var userInfoResponse = await userInfoClient.GetAsync();

                        //// create new identity
                        var id = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                        id.AddClaims(userInfoResponse.GetClaimsIdentity().Claims);

                        id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        id.AddClaim(new Claim("access_token", tokenResponse.AccessToken));
                        id.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString()));
                        if (tokenResponse.RefreshToken != null)
                        {
                            id.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));
                        }
                        //id.AddClaim(new Claim("sid", n.AuthenticationTicket.Identity.FindFirst("sid").Value));

                        n.AuthenticationTicket = new AuthenticationTicket(
                            new ClaimsIdentity(id.Claims, n.AuthenticationTicket.Identity.AuthenticationType),
                            n.AuthenticationTicket.Properties);
                    },

                //    RedirectToIdentityProvider = n =>
                //    {
                //        // if signing out, add the id_token_hint
                //        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                //        {
                //            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                //            if (idTokenHint != null)
                //            {
                //                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                //            }

                //        }

                //        return Task.FromResult(0);
                //    }
                }

            });

            //app.UseOktaBearerTokenAuthentication(new OktaBearerTokenAuthenticationOptions
            //{
            //    OrganizationUrl = System.Configuration.ConfigurationManager.AppSettings["OpenIDConnect_Authority"],
            //    ClientId = System.Configuration.ConfigurationManager.AppSettings["OpenIDConnect_ClientId"],
            //});


        }
    }
}
