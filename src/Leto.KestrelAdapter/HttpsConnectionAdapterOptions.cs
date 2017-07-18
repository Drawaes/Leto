using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Leto.KestrelAdapter
{
    public class HttpsConnectionAdapterOptions
    {
        public HttpsConnectionAdapterOptions()
        {
            ClientCertificateMode = ClientCertificateMode.NoCertificate;
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11;
        }

        public string ServerCertificate { get; set; }
        public string Password { get; set; }
        public ClientCertificateMode ClientCertificateMode { get; set; }
        public Func<X509Certificate2, X509Chain, SslPolicyErrors, bool> ClientCertificateValidation { get; set; }
        public SslProtocols SslProtocols { get; set; }
        public bool CheckCertificateRevocation { get; set; }
    }
}
