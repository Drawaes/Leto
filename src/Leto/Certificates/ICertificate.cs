using Leto.Hashes;
using System;
using Leto.Internal;

namespace Leto.Certificates
{
    public interface ICertificate
    {
        CertificateType CertificateType { get; }
        byte[] CertificateData { get; }
        byte[][] CertificateChain { get; }
        int SignatureSize { get; }
        SignatureScheme SelectAlgorithm(BigEndianAdvancingSpan buffer);
        bool SupportsScheme(SignatureScheme scheme);
        int SignHash(IHashProvider provider, SignatureScheme scheme, Span<byte> message, Span<byte> output);
        int Decrypt(SignatureScheme scheme, Span<byte> encryptedData, Span<byte> output);
    }
}
