using Leto.Windows;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.WindowsFacts
{
    public class ClientSslStreamFacts
    {
        [Fact]
        public async Task HandshakeCompletes()
        {
            using (var factory = new PipeFactory())
            using (var listener = new WindowsSecurePipeListener(Data.Certificates.RSACertificate, factory))
            {
                var loopback = new LoopbackPipeline(factory);
                var stream = loopback.ClientPipeline.GetStream();
                var secureConnection = listener.CreateConnection(loopback.ServerPipeline);
                using (var sslStream = new SslStream(stream, false, CertVal))
                {
                    await sslStream.AuthenticateAsClientAsync("localhost");
                }
                var loopback2 = new LoopbackPipeline(factory);
                var stream2 = loopback2.ClientPipeline.GetStream();
                var secureConnection2 = listener.CreateConnection(loopback2.ServerPipeline);
                using (var sslStream2 = new SslStream(stream2, false, CertVal))
                {
                    await sslStream2.AuthenticateAsClientAsync("localhost");
                }
            }
        }

        private bool CertVal(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors policyError) => true;
        
        [Fact]
        public void SocketTest()
        {
            using (var factory = new PipeFactory())
            using (var listener = new System.IO.Pipelines.Networking.Sockets.SocketListener())
            using (var secureListener = new WindowsSecurePipeListener(Data.Certificates.RSACertificate))
            {
                listener.OnConnection(async (conn) =>
                {
                    var pipe = await secureListener.CreateConnection(conn);
                    Console.WriteLine("Handshake Done");
                    var reader = await pipe.Input.ReadAsync();
                    System.Diagnostics.Debug.WriteLine(Encoding.UTF8.GetString(reader.Buffer.ToArray()));
                });
                listener.Start(new IPEndPoint(IPAddress.Any, 443));
                Console.ReadLine();
            }
        }
    }
}
