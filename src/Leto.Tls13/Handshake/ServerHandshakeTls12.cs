using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class ServerHandshakeTls12
    {
        public static WritableBuffer SendCertificates(WritableBuffer buffer, IConnectionState connectionState)
        {
            BufferExtensions.WriteVector24Bit(ref buffer, (writer, state) =>
            {
                WriteCertificateEntry(ref writer, connectionState.Certificate.CertificateData);
                foreach(var b in connectionState.Certificate.CertificateChain)
                {
                    WriteCertificateEntry(ref writer, b);
                }
                return buffer;
            }, connectionState);
            return buffer;
        }

        public static void WriteCertificateEntry(ref WritableBuffer writer, byte[] certificate)
        {
            writer.Ensure(3);
            writer.Memory.Write24BitNumber(certificate.Length);
            writer.Advance(3);
            writer.Write(certificate);
        }
    }
}
