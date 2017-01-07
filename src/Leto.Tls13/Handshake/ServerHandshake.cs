using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class ServerHandshake
    {
        public static void SendFlightOne(ref WritableBuffer writer, ConnectionState connectionState)
        {
            connectionState.WriteHandshake(ref writer, HandshakeType.encrypted_extensions, (Buffer, state) =>
            {
                BufferExtensions.WriteVector<ushort>(ref Buffer, Extensions.WriteExtensionList, state);
                return Buffer;
            });
            connectionState.WriteHandshake(ref writer, HandshakeType.certificate, WriteCertificate);
        }

        public static WritableBuffer WriteCertificate(WritableBuffer writer, ConnectionState connectionState)
        {
            //writer.WriteBigEndian<byte>(0);
            BufferExtensions.WriteVector24Bit(ref writer, (buffer, state) =>
            {
                WriteCertificateEntry(ref buffer, state.Certificate);
                return buffer;
            }, connectionState);
            return writer;
        }

        public static void WriteCertificateEntry(ref WritableBuffer writer, ICertificate certificate)
        {
            writer.Ensure(3);
            writer.Memory.Write24BitNumber(certificate.CertificateData.Length);
            writer.Advance(3);
            writer.Write(certificate.CertificateData);
            //writer.WriteBigEndian<ushort>(0);
        }

        internal static void SendServerCertificate(ref WritableBuffer writer, ConnectionState connectionState)
        {
            
        }
    }
}
