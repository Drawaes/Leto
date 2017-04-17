using System;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using System.Buffers;

namespace SocketServer
{
    class Program
    {
        static void Main(string[] args)
        {
            for (var i = 0; i < 100; i++)
            {
                var streamFacts = new Leto.OpenSslFacts.ClientSslStreamFacts();
                streamFacts
                    .HandshakeCompletes(Leto.CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
                    .Wait();
            }
            using (var factory = new PipeFactory())
            using (var listener = new System.IO.Pipelines.Networking.Sockets.SocketListener())
            using (var secureListener = new Leto.OpenSsl11.OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                listener.OnConnection(async (conn) =>
                {
                    var pipe = await secureListener.CreateConnection(conn);
                    Console.WriteLine("Handshake Done");
                    var writer = pipe.Output.Alloc();
                    writer.WriteBigEndian<long>(0);
                    await writer.FlushAsync();
                    pipe.Output.Complete();
                    Console.WriteLine("Connection Done");

                });
                listener.Start(new IPEndPoint(IPAddress.Any, 443));
                Console.ReadLine();
            }
        }
    }
}