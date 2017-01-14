using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Leto.Tls13;
using Xunit;

namespace Leto.Tls13Facts
{
    public class SocketFacts
    {
        [Fact]
        public async Task WaitForConnectionFact()
        {
            using (var factory = new PipelineFactory())
            using (var cert = new X509Certificate2(CertificateFacts._certificatePath, CertificateFacts._certificatePassword, X509KeyStorageFlags.Exportable))
            using (var cert2 = new X509Certificate2(CertificateFacts._ecdsaCertificate, CertificateFacts._certificatePassword, X509KeyStorageFlags.Exportable))
            using (var list = new CertificateList())
            {
                //list.AddCertificate(cert);
                list.AddCertificate(cert2);
                //list.AddPEMCertificate(CertificateFacts.rsaCertPEM, CertificateFacts.rsaKeyPEM);
                //list.AddPEMCertificate(CertificateFacts.ecdsaCertPEM, CertificateFacts.ecdsaKeyPEM);
                using (var serverContext = new SecurePipelineListener(factory, list))
                //using (var socketClient = new System.IO.Pipelines.Networking.Sockets.SocketListener(factory))
                {
                    var ipEndPoint = new IPEndPoint(IPAddress.Loopback, 443);
                    //socketClient.OnConnection(async s =>
                    //{
                    //    var sp = serverContext.CreateSecurePipeline(s);
                    //    await Echo(sp);
                    //});
                    //socketClient.Start(ipEndPoint);

                    var socket = await System.IO.Pipelines.Networking.Sockets.SocketConnection.ConnectAsync(ipEndPoint);
                    var clientPipe = serverContext.CreateSecureClientPipeline(socket);
                    var buffer = clientPipe.Output.Alloc();
                    var sb = new StringBuilder();
                    sb.AppendLine("HTTP/1.1 200 OK");
                    sb.AppendLine("Content-Length: 13");
                    sb.Append("Content-Type: text/plain");
                    sb.Append("\r\n\r\n");
                    sb.Append("Hello, World!");
                    buffer.Write(Encoding.ASCII.GetBytes(sb.ToString()));
                    await buffer.FlushAsync();
                    Console.ReadLine();
                }
            }
        }

        private async Task Echo(SecurePipelineConnection pipeline)
        {
            try
            {
                while (true)
                {
                    var result = await pipeline.Input.ReadAsync();
                    var request = result.Buffer;

                    if (request.IsEmpty && result.IsCompleted)
                    {
                        pipeline.Input.Advance(request.End);
                        break;
                    }
                    int len = request.Length;
                    var response = pipeline.Output.Alloc();
                    var sb = new StringBuilder();
                    sb.AppendLine("HTTP/1.1 200 OK");
                    sb.AppendLine("Content-Length: 13");
                    sb.Append("Content-Type: text/plain");
                    sb.Append("\r\n\r\n");
                    sb.Append("Hello, World!");
                    response.Write(Encoding.UTF8.GetBytes(sb.ToString()));
                    await response.FlushAsync();
                    pipeline.Input.Advance(request.End);
                    return;
                }
                pipeline.Input.Complete();
                pipeline.Output.Complete();
            }
            catch (Exception ex)
            {
                pipeline.Input.Complete(ex);
                pipeline.Output.Complete(ex);
            }
        }
    }
}
