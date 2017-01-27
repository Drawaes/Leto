using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
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
        public unsafe void WaitForConnectionFact()
        {
            //uint count;
            //Tls13.Interop.Test.NCryptProviderName* providerList;
            //Leto.Tls13.Interop.Test.NCryptEnumStorageProviders(out count, out providerList, 0 );

            //for(int i = 0; i < count; i++)
            //{
            //    var prov = providerList[i];
            //    Console.WriteLine(Marshal.PtrToStringUni(prov.pszName));
            //    Console.WriteLine(Marshal.PtrToStringUni(prov.pszComment));
            //}

            //using (var factory = new PipelineFactory())
            //using (var cert = new X509Certificate2(CertificateFacts._certificatePath, CertificateFacts._certificatePassword, X509KeyStorageFlags.Exportable))
            //using (var cert2 = new X509Certificate2(CertificateFacts._ecdsaCertificate, CertificateFacts._certificatePassword, X509KeyStorageFlags.Exportable))
            //using (var list = new CertificateList())
            //{
            //    //list.AddCertificate(cert);
            //    list.AddCertificate(cert2);
            //    //list.AddPEMCertificate(CertificateFacts.rsaCertPEM, CertificateFacts.rsaKeyPEM);
            //    //list.AddPEMCertificate(CertificateFacts.ecdsaCertPEM, CertificateFacts.ecdsaKeyPEM);
            //    using (var serverContext = new SecurePipelineListener(factory, list))
            //    {
            //        serverContext.CertificateValidation = CertificateValidation;
            //        var addresses = Dns.GetHostAddressesAsync("tls13.cloudflare.com").Result;
            //        var ipEndPoint = new IPEndPoint(addresses.First(), 443);

            //        var socket = await System.IO.Pipelines.Networking.Sockets.SocketConnection.ConnectAsync(ipEndPoint);
            //        var clientPipe = serverContext.CreateSecureClientPipeline(socket);
            //        var buffer = clientPipe.Output.Alloc();
            //        var sb = new StringBuilder();
            //        sb.AppendLine("HTTP/1.1 200 OK");
            //        sb.AppendLine("Content-Length: 13");
            //        sb.Append("Content-Type: text/plain");
            //        sb.Append("\r\n\r\n");
            //        sb.Append("Hello, World!");
            //        buffer.Write(Encoding.ASCII.GetBytes(sb.ToString()));
            //        await buffer.FlushAsync();
            //        Console.ReadLine();
            //    }
            //}
        }

        private bool CertificateValidation(X509Certificate2Collection certificateCollection)
        {
            return true;
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
