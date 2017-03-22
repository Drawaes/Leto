using Leto.Certificates;
using System;
using System.IO.Pipelines;

namespace Leto.Handshake
{
    public static class CertificateWriter
    {
        public static WritableBuffer WriteCertificates(WritableBuffer buffer, ICertificate certificate)
        {
            void WriteCertificate(ref WritableBuffer writer, Span<byte> certData)
            {
                writer.Ensure(3);
                writer.Buffer.Span.Write24BitNumber(certData.Length);
                writer.Advance(3);
                writer.Write(certData);
            }
            BufferExtensions.WriteVector24Bit(ref buffer, (writer) =>
            {
                WriteCertificate(ref writer, certificate.CertificateData);
                foreach (var b in certificate.CertificateChain)
                {
                    WriteCertificate(ref writer, b);
                }
                return writer;
            });
            return buffer;
        }
    }
}
