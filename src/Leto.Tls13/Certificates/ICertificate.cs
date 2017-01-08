using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Hash;

namespace Leto.Tls13.Certificates
{
    public interface ICertificate:IDisposable
    {
        byte[] CertificateData { get; }
        CertificateType CertificateType { get; }
        string HostName { get;}
        bool SupportsSignatureScheme(SignatureScheme scheme);
        int SignatureSize(SignatureScheme scheme);
        unsafe Span<byte> SignHash(IHashProvider provider, SignatureScheme scheme, byte* message, int messageLength);
    }
}