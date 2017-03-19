using Leto.Hashes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Certificates
{
    public interface ICertificate
    {
        CertificateType CertificateType { get; }
        byte[] CertificateData { get; }
        byte[][] CertificateChain { get; }
        int SignatureSize { get; }
        SignatureScheme SelectAlgorithm(Span<byte> buffer);
        int SignHash(IHashProvider provider, SignatureScheme scheme, Span<byte> message, Span<byte> output);
        int Decrypt(SignatureScheme scheme, Span<byte> encryptedData, Span<byte> output);
    }
}
