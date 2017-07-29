using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.IO.Pipelines.Networking.Sockets;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Leto.OpenSsl11;
using System.Threading.Tasks;
using System.IO;
using LegacyOpenSsl;

namespace SocketServer
{
    public class RawSocketOpenSslLegacy : RawHttpServerSampleBase
    {
        public RawSocketOpenSslLegacy(string filename)
            : base(filename)
        {
        }

        public SocketListener Listener { get; private set; }

        private PipeFactory _factory = new PipeFactory();
        private LegacyStreamFactory _streamFactory;

        protected override Task Start(IPEndPoint ipEndpoint)
        {
            _streamFactory = new LegacyStreamFactory("../TLSCerts/server.pfx", "test");
            Listener = new SocketListener();
            Listener.OnConnection(async connection => { await ProcessConnection(await CreateSslStream(connection)); });

            Listener.Start(ipEndpoint);
            return Task.CompletedTask;
        }

        private async Task<IPipeConnection> CreateSslStream(SocketConnection connection)
        {
            var sslStream = _streamFactory.GetStream(connection.GetStream());
            try
            {
                await sslStream.AuthenticateAsServerAsync();
            }
            catch
            {
                sslStream.Dispose();
                return null;
            }
            var returnConnection = new SslStreamConnection()
            {
                Input = _factory.CreateReader(sslStream),
                Output = _factory.CreateWriter(sslStream),
            };
            return returnConnection;
        }

        private class SslStreamConnection : IPipeConnection
        {
            public IPipeReader Input { get; set; }

            public IPipeWriter Output { get; set; }

            public void Dispose() { }
        }

        protected override Task Stop()
        {
            Listener.Dispose();
            return Task.CompletedTask;
        }
    }
}
