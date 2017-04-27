using System.Net.Http;
using System.Threading.Tasks;
using Leto.WindowsAuthentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Leto.MiddlewareFacts
{
    public class NtlmFacts
    {
        [Fact]
        public async Task CanAuthenticateWithNtlm()
        {
            var host = new WebHostBuilder()
                .UseKestrel((ops) =>
                {
                    ops.UseWindowsAuthentication();
                })
                .UseUrls($"http://*:{55555}")
                .UseStartup<Startup>()
                .Build();
            host.Start();

            try
            {
                var client = new HttpClient(new HttpClientHandler()
                {
                    UseDefaultCredentials = true
                });
                var result = await client.GetAsync($"http://localhost:55555");
                var name = await result.Content.ReadAsStringAsync();
                Assert.Equal(System.Security.Principal.WindowsIdentity.GetCurrent().Name, name);
            }
            finally
            {
                host.Dispose();
            }
        }

        public class Startup
        {
            public void Configure(IApplicationBuilder app)
            {
                app.UseWindowsAuthentication();
                app.Use(async (context, next) =>
                {
                    await context.Response.WriteAsync(context.User.Identity.Name);
                    return;
                });
            }
        }
    }
}
