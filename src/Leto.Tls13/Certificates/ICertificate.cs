using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Certificates
{
    public interface ICertificate:IDisposable
    {
        byte[] CertificateData { get; }
        CertificateType CertificateType { get; }
        string HostName { get;}
        bool SupportsSignatureScheme(SignatureScheme scheme);
    }
}