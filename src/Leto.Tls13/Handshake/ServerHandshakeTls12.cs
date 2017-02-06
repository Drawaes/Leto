using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class ServerHandshakeTls12
    {
        public static WritableBuffer SendCertificates(WritableBuffer buffer, IConnectionStateTls12 connectionState)
        {
            var startOfMessage = buffer.BytesWritten;
            BufferExtensions.WriteVector24Bit(ref buffer, (writer, state) =>
            {
                WriteCertificateEntry(ref writer, connectionState.Certificate.CertificateData);
                foreach (var b in connectionState.Certificate.CertificateChain)
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

        public unsafe static WritableBuffer SendKeyExchange(WritableBuffer buffer, IConnectionStateTls12 connectionState)
        {
            var messageLength = 4 + connectionState.KeyShare.KeyExchangeSize;
            buffer.Ensure(messageLength);
            var bookMark = buffer.Memory;
            buffer.WriteBigEndian(ECCurveType.named_curve);
            buffer.WriteBigEndian(connectionState.KeyShare.NamedGroup);
            buffer.WriteBigEndian((byte)connectionState.KeyShare.KeyExchangeSize);
            connectionState.KeyShare.WritePublicKey(ref buffer);

            buffer.WriteBigEndian(connectionState.SignatureScheme);
            buffer.WriteBigEndian((ushort)connectionState.Certificate.SignatureSize(connectionState.SignatureScheme));
            var tempBuffer = stackalloc byte[connectionState.ClientRandom.Length * 2 + messageLength];
            var tmpSpan = new Span<byte>(tempBuffer, connectionState.ClientRandom.Length * 2 + messageLength);
            connectionState.ClientRandom.CopyTo(tmpSpan);
            tmpSpan = tmpSpan.Slice(connectionState.ClientRandom.Length);
            connectionState.ServerRandom.CopyTo(tmpSpan);
            tmpSpan = tmpSpan.Slice(connectionState.ServerRandom.Length);
            bookMark.Span.Slice(0, messageLength).CopyTo(tmpSpan);
            connectionState.Certificate.SignHash(connectionState.CryptoProvider.HashProvider,
                connectionState.SignatureScheme, ref buffer, tempBuffer, connectionState.ClientRandom.Length * 2 + messageLength);
            return buffer;
        }
    }
}
