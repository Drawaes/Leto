using Leto.OpenSsl11;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using CommonFacts;
using System.Diagnostics;

namespace Leto.OpenSslFacts
{
    public class ClientSslStreamFacts
    {
        [Theory]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.RSA_AES_128_GCM_SHA256)]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.RSA_AES_256_GCM_SHA384)]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)]
        public async Task HandshakeCompletes(CipherSuites.PredefinedCipherSuites.PredefinedSuite suite)
        {
            using (var factory = new PipeFactory())
            using (var listener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate, factory))
            {
                listener.CryptoProvider.CipherSuites.SetCipherSuites(new CipherSuites.CipherSuite[] { CipherSuites.PredefinedCipherSuites.GetSuiteByName(suite) });
                var loopback = new LoopbackPipeline(factory);
                var stream = loopback.ClientPipeline.GetStream();
                var secureConnection = listener.CreateConnection(loopback.ServerPipeline);
                var ignore = Echo(secureConnection);
                using (var sslStream = new SslStream(stream, false, CertVal))
                {
                    await sslStream.AuthenticateAsClientAsync("localhost");
                    var bytes = Encoding.UTF8.GetBytes("Hello World");

                    await sslStream.WriteAsync(bytes, 0, bytes.Length);
                    var byteCount = await sslStream.ReadAsync(bytes, 0, bytes.Length);
                }
            }
        }

        private bool CertVal(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors policyError) => true;

        private async Task Echo(Task<SecurePipeConnection> connectionTask)
        {
            var connection = await connectionTask;
            var readResult = await connection.Input.ReadAsync();
            var writer = connection.Output.Alloc();
            writer.Append(readResult.Buffer);
            await writer.FlushAsync();
        }

        [Fact]
        public void SocketTest()
        {
            using (var factory = new PipeFactory())
            using (var listener = new System.IO.Pipelines.Networking.Sockets.SocketListener())
            using (var secureListener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                listener.OnConnection(async (conn) =>
                {
                    var pipe = await secureListener.CreateConnection(conn);
                    Console.WriteLine("Handshake Done");
                    var reader = await pipe.Input.ReadAsync();
                    Debug.WriteLine(Encoding.UTF8.GetString(reader.Buffer.ToArray()));
                    var writer = pipe.Output.Alloc();
                    writer.Append(reader.Buffer);
                    await writer.FlushAsync();
                });
                listener.Start(new IPEndPoint(IPAddress.Any, 443));

                //var process = new Process();
                //process.StartInfo.FileName = @"C:\code\nssclean\TestClient\RunTest.bat";
                //process.Start();
                //process.BeginOutputReadLine();
                
                Console.ReadLine();
            }
        }
    }
}
