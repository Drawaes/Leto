using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.IO.Pipelines.Networking.Sockets;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SocketServer
{
    public class RawSocketSslStream : RawHttpServerSampleBase
    {
        public RawSocketSslStream(string filename)
            :base(filename)
        {

        }

        public SocketListener Listener { get; private set; }

        private PipeFactory _factory = new PipeFactory();
        private X509Certificate2 _certificate;

        protected override Task Start(IPEndPoint ipEndpoint)
        {
            _certificate = new X509Certificate2("../TLSCerts/server.pfx", "test");
            Listener = new SocketListener();
            Listener.OnConnection(async connection => { await ProcessConnection(await CreateSslStream(connection)); });

            Listener.Start(ipEndpoint);
            return Task.CompletedTask;
        }

        private async Task<IPipeConnection> CreateSslStream(SocketConnection connection)
        {
            var sslStream = new SslStream(connection.GetStream());
            await sslStream.AuthenticateAsServerAsync(_certificate);
            var returnConnection = new SslStreamConnection()
            {
                Input = _factory.CreateReader(sslStream),
                Output = _factory.CreateWriter(sslStream)
            };
            return returnConnection;
        }

        private class SslStreamConnection : IPipeConnection
        {
            public IPipeReader Input { get; set; }

            public IPipeWriter Output { get; set; }

            public void Dispose() => throw new NotImplementedException();
        }

        protected override Task Stop()
        {
            Listener.Dispose();
            return Task.CompletedTask;
        }
    }
}
