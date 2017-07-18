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
using Leto.SslStream2;

namespace SocketServer
{
    public class RawSocketSslStream2 : RawHttpServerSampleBase
    {
        public RawSocketSslStream2(string filename)
            : base(filename)
        {
        }

        public SocketListener Listener { get; private set; }

        private PipeFactory _factory = new PipeFactory();
        private SslStream2Factory _streamFactory;

        protected override Task Start(IPEndPoint ipEndpoint)
        {
            _streamFactory = new SslStream2Factory("../TLSCerts/server.pfx", "test");
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
                Console.WriteLine($"Trying to connect on {sslStream.ConnectionId}");
                await sslStream.AuthenticateAsServerAsync();
                Console.WriteLine($"Connected on {sslStream.ConnectionId}");
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Failed to connect on {sslStream.ConnectionId} - error {ex}");
                sslStream.Dispose();

                return null;
            }
            var returnConnection = new SslStreamConnection()
            {
                InternalStream = sslStream,
                Input = _factory.CreateReader(sslStream),
                Output = _factory.CreateWriter(sslStream),
            };
            return returnConnection;
        }

        private class SslStreamConnection : IPipeConnection
        {
            internal Stream InternalStream;

            public IPipeReader Input { get; set; }

            public IPipeWriter Output { get; set; }

            public void Dispose() => InternalStream.Dispose();
        }

        protected override Task Stop()
        {
            Listener.Dispose();
            return Task.CompletedTask;
        }
    }
}
