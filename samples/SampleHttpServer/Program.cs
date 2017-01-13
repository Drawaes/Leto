using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Leto.Tls13;
using Microsoft.Extensions.PlatformAbstractions;

namespace SampleHttpServer
{
    public class Program
    {
        public const string ecdsaCertPEM = @"-----BEGIN CERTIFICATE-----
MIIB/jCCAWICCQDscdUxw16XFDAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTI0MDQ4WhcNMTUxMTE0MTI0MDQ4WjBFMQswCQYDVQQG
EwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lk
Z2l0cyBQdHkgTHRkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBY9+my9OoeSUR
lDQdV/x8LsOuLilthhiS1Tz4aGDHIPwC1mlvnf7fg5lecYpMCrLLhauAc1UJXcgl
01xoLuzgtAEAgv2P/jgytzRSpUYvgLBt1UA0leLYBy6mQQbrNEuqT3INapKIcUv8
XxYP0xMEUksLPq6Ca+CRSqTtrd/23uTnapkwCQYHKoZIzj0EAQOBigAwgYYCQXJo
A7Sl2nLVf+4Iu/tAX/IF4MavARKC4PPHK3zfuGfPR3oCCcsAoz3kAzOeijvd0iXb
H5jBImIxPL4WxQNiBTexAkF8D1EtpYuWdlVQ80/h/f4pBcGiXPqX5h2PQSQY7hP1
+jwM1FGS4fREIOvlBYr/SzzQRtwrvrzGYxDEDbsC0ZGRnA==
-----END CERTIFICATE-----
";

        public const string ecdsaKeyPEM = @"-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBrsoKp0oqcv6/JovJJDoDVSGWdirrkgCWxrprGlzB9o0X8fV675X0
NwuBenXFfeZvVcwluO7/Q9wkYoPd/t3jGImgBwYFK4EEACOhgYkDgYYABAFj36bL
06h5JRGUNB1X/Hwuw64uKW2GGJLVPPhoYMcg/ALWaW+d/t+DmV5xikwKssuFq4Bz
VQldyCXTXGgu7OC0AQCC/Y/+ODK3NFKlRi+AsG3VQDSV4tgHLqZBBus0S6pPcg1q
kohxS/xfFg/TEwRSSws+roJr4JFKpO2t3/be5OdqmQ==
-----END EC PRIVATE KEY-----
";

        public const string rsaCertPEM = @"-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJAI/M7BYjwB+uMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJ
hPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNa
rtNuC+BdZ1tMuVCPFZcCAwEAAaNQME4wHQYDVR0OBBYEFJvKs8RfJaXTH08W+SGv
zQyKn0H8MB8GA1UdIwQYMBaAFJvKs8RfJaXTH08W+SGvzQyKn0H8MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADQQBJlffJHybjDGxRMqaRmDhX0+6v02TUKZsW
r5QuVbpQhH6u+0UgcW0jp9QwpxoPTLTWGXEWBBBurxFwiCBhkQ+V
-----END CERTIFICATE-----
";

        public const string rsaKeyPEM = @"-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END RSA PRIVATE KEY-----
";
        public static readonly string _rsaCertPath = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath, "data", "TestCert.pfx");
        public static readonly string _ecdsaCertPath = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath, "data", "certificate.pfx");
        public static readonly string _certificatePassword = "Test123t";

        public static void Main(string[] args)
        {
            using (var cert = new X509Certificate2(_rsaCertPath, _certificatePassword, X509KeyStorageFlags.Exportable))
            using (var cert2 = new X509Certificate2(_ecdsaCertPath, _certificatePassword, X509KeyStorageFlags.Exportable))
            using (var factory = new PipelineFactory())
            using (var list = new CertificateList())
            {
                list.AddCertificate(cert);
                list.AddCertificate(cert2);
                list.AddPEMCertificate(rsaCertPEM, rsaKeyPEM);
                using (var serverContext = new SecurePipelineListener(factory, list))
                using (var socketClient = new System.IO.Pipelines.Networking.Sockets.SocketListener(factory))
                {
                    var ip = IPAddress.Loopback;
                    int port = 443;
                    var ipEndPoint = new IPEndPoint(ip, port);
                    socketClient.OnConnection(async s =>
                    {
                        var sp = serverContext.CreateSecurePipeline(s);
                        await Echo(sp);
                    });
                    socketClient.Start(ipEndPoint);
                    Console.ReadLine();
                }
            }
        }

        private static async Task Echo(SecurePipelineConnection pipeline)
        {
            try
            {
                var result = await pipeline.Input.ReadAsync();
                var request = result.Buffer;

                if (request.IsEmpty && result.IsCompleted)
                {
                    pipeline.Input.Advance(request.End);
                    return;
                }
                int len = request.Length;
                var response = pipeline.Output.Alloc();
                var sb = new StringBuilder();
                sb.AppendLine("HTTP/1.1 200 OK");
                sb.AppendLine("Content-Length: " + request.Length);
                sb.AppendLine("Content-Type: text/plain");
                sb.AppendLine("Connection: close");
                response.Write(Encoding.UTF8.GetBytes(sb.ToString()));
                response.Append(request);
                await response.FlushAsync();
                pipeline.Input.Advance(request.End);

            }
            finally
            {
                pipeline.Input.Complete();
                pipeline.Output.Complete();
            }
        }
    }
}
