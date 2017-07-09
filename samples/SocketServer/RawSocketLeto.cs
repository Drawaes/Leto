using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.IO.Pipelines.Networking.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SocketServer
{
    public class RawSocketLeto : RawHttpServerSampleBase
    {
        public SocketListener Listener { get; private set; }

        private Leto.OpenSsl11.OpenSslSecurePipeListener _secure;

        protected override Task Start(IPEndPoint ipEndpoint)
        {
            var certificate = new X509Certificate2("../TLSCerts/server.pfx", "test");
            var newCert = new Leto.Certificates.ManagedCertificate(certificate, null);
            _secure = new Leto.OpenSsl11.OpenSslSecurePipeListener(newCert);

            Listener = new SocketListener();
            Listener.OnConnection(async connection => { await CreateConnection(connection); });

            Listener.Start(ipEndpoint);
            return Task.CompletedTask;
        }

        private async Task CreateConnection(SocketConnection connection)
        {
            var secConnection = await _secure.CreateConnection(connection);
            await ProcessConnection(secConnection);
        }

        protected override Task Stop()
        {
            Listener.Dispose();
            return Task.CompletedTask;
        }
    }
}
