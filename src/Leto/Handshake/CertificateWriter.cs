using Leto.Certificates;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace Leto.Handshake
{
    public static class CertificateWriter
    {
        private static void WriteCertificateEntry(ref WritableBuffer writer, Span<byte> certificate)
        {
            writer.Ensure(3);
            writer.Memory.Span.Write24BitNumber(certificate.Length);
            writer.Advance(3);
            writer.Write(certificate);
        }

        public static WritableBuffer WriteCertificates(WritableBuffer buffer, ICertificate certificate)
        {
            var startOfMessage = buffer.BytesWritten;
            BufferExtensions.WriteVector24Bit(ref buffer, (writer) =>
            {
                WriteCertificateEntry(ref writer, certificate.CertificateData);
                foreach (var b in certificate.CertificateChain)
                {
                    WriteCertificateEntry(ref writer, b);
                }
                return writer;
            });
            return buffer;
        }
    }
}
