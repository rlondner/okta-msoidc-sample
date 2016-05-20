using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(OktaOpenIDConnect.Startup))]

namespace OktaOpenIDConnect
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
