using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Leto.Tls13.Certificates
{
    public interface ICertificateProvider
    {
        ICertificate LoadCertificate(string certificate, string privateKey);
        ICertificate LoadCertificate(X509Certificate2 certificate);
    }
}
