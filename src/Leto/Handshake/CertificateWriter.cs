using Leto.Certificates;
using System;
using System.IO.Pipelines;
using Leto.Internal;

namespace Leto.Handshake
{
    public static class CertificateWriter
    {
        public static WritableBuffer WriteCertificates(WritableBuffer buffer, ICertificate certificate)
        {
            void WriteCertificate(ref WritableBuffer writer, Span<byte> certData)
            {
                writer.Ensure(3);
                writer.WriteBigEndian((UInt24)certData.Length);
                writer.Write(certData);
            }
            BufferExtensions.WriteVector<UInt24>(ref buffer, (ref WritableBuffer writer) =>
            {
                WriteCertificate(ref writer, certificate.CertificateData);
                foreach (var b in certificate.CertificateChain)
                {
                    WriteCertificate(ref writer, b);
                }
            });
            return buffer;
        }
    }
}
