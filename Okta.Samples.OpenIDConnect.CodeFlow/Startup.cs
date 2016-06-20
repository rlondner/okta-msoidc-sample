using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(Okta.Samples.OpenIDConnect.CodeFlow.Startup))]

namespace Okta.Samples.OpenIDConnect.CodeFlow
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
