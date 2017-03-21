﻿using Leto.OpenSsl11;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class ClientSslStreamFacts
    {
        [Fact]
        public async Task HandshakeCompletes()
        {
            using (var factory = new PipeFactory())
            {
                var loopback = new LoopbackPipeline(factory);
                var stream = loopback.ClientPipeline.GetStream();
                var secureConnection = new SecurePipeConnection(factory, loopback.ServerPipeline, new OpenSslSecurePipeListener(Data.Certificates.RSACertificate));
                using (var sslStream = new SslStream(stream, false, CertVal))
                {
                    await sslStream.AuthenticateAsClientAsync("localhost");
                }
            }
        }

        private bool CertVal(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors policyError)
        {
            return true;
        }

        [Fact]
        public void SocketTest()
        {
            using (var factory = new PipeFactory())
            using (var listener = new System.IO.Pipelines.Networking.Sockets.SocketListener())
            {
                var secureListener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate);
                listener.OnConnection(async (conn) =>
                {
                    var pipe = new SecurePipeConnection(factory, conn, secureListener);
                    await pipe.HandshakeAwaiter;
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
