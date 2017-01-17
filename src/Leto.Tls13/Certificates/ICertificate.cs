using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Hash;

namespace Leto.Tls13.Certificates
{
    public interface ICertificate : IDisposable
    {
        byte[] CertificateData { get; }
        byte[][] CertificateChain { get; }
        CertificateType CertificateType { get; }
        string HostName { get; }
        bool SupportsSignatureScheme(SignatureScheme scheme);
        int SignatureSize(SignatureScheme scheme);
        unsafe int SignHash(IHashProvider provider, SignatureScheme scheme, ref WritableBuffer writer, byte* message, int messageLength);
    }
}