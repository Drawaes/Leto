using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;

namespace SocketServer
{
    public abstract class HttpServerBase : IServer
    {
        public IFeatureCollection Features { get; } = new FeatureCollection();

        public HttpServerBase() => Features.Set<IServerAddressesFeature>(new ServerAddressesFeature());

        public Task StartAsync<TContext>(IHttpApplication<TContext> application, CancellationToken token)
        {
            var feature = Features.Get<IServerAddressesFeature>();
            var address = feature.Addresses.FirstOrDefault();
            GetIp(address, out var ip, out var port);
            Task.Run(() => StartAccepting(application, ip, port));
            return Task.FromResult(0);
        }

        protected abstract void StartAccepting<TContext>(IHttpApplication<TContext> application, IPAddress ip, int port);

        private static void GetIp(string url, out IPAddress ip, out int port)
        {
            ip = null;

            var address = ServerAddress.FromUrl(url);
            switch (address.Host)
            {
                case "localhost":
                    ip = IPAddress.Loopback;
                    break;
                case "*":
                    ip = IPAddress.Any;
                    break;
                default:
                    break;
            }
            ip = ip ?? IPAddress.Parse(address.Host);
            port = address.Port;
        }
        
        public virtual void Dispose()
        {
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.FromResult(0);
    }
}
