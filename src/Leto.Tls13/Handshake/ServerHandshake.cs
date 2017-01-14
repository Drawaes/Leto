using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.Internal;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class ServerHandshake
    {
        public static void SendFlightOne(ref WritableBuffer writer, IConnectionState connectionState)
        {
            connectionState.WriteHandshake(ref writer, HandshakeType.encrypted_extensions, (buffer, state) =>
            {
                BufferExtensions.WriteVector<ushort>(ref buffer, Extensions.WriteExtensionList, state);
                return buffer;
            });
            if (connectionState.PskIdentity == -1)
            {
                connectionState.WriteHandshake(ref writer, HandshakeType.certificate, WriteCertificate);
                connectionState.WriteHandshake(ref writer, HandshakeType.certificate_verify, SendCertificateVerify);
            }
        }

        public static WritableBuffer WriteCertificate(WritableBuffer writer, IConnectionState connectionState)
        {
            writer.WriteBigEndian<byte>(0);
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
            writer.WriteBigEndian<ushort>(0);
        }

        public unsafe static WritableBuffer SendCertificateVerify(WritableBuffer writer, IConnectionState state)
        {
            writer.WriteBigEndian(state.SignatureScheme);
            var bookMark = writer.Memory;
            writer.WriteBigEndian((ushort)0);
            var hash = new byte[state.HandshakeHash.HashSize + Tls1_3Labels.SignatureDigestPrefix.Length + Tls1_3Labels.ServerCertificateVerify.Length];
            Tls1_3Labels.SignatureDigestPrefix.CopyTo(hash, 0);
            Tls1_3Labels.ServerCertificateVerify.CopyTo(hash, Tls1_3Labels.SignatureDigestPrefix.Length);
            fixed (byte* hPtr = hash)
            {
                var sigPtr = hPtr + Tls1_3Labels.SignatureDigestPrefix.Length + Tls1_3Labels.ServerCertificateVerify.Length;
                state.HandshakeHash.InterimHash(sigPtr, state.HandshakeHash.HashSize);
                var sigSize = state.Certificate.SignHash(state.CryptoProvider.HashProvider, state.SignatureScheme, ref writer, hPtr, hash.Length);
                bookMark.Span.Write16BitNumber((ushort)sigSize);
            }
            return writer;
        }

        public static unsafe void ServerFinished(ref WritableBuffer writer, IConnectionState connectionState, byte[] finishedKey)
        {
            var hash = new byte[connectionState.HandshakeHash.HashSize];
            fixed (byte* hPtr = hash)
            fixed (byte* kPtr = finishedKey)
            {
                connectionState.HandshakeHash.InterimHash(hPtr, hash.Length);
                connectionState.CryptoProvider.HashProvider.HmacData(connectionState.CipherSuite.HashType, kPtr, finishedKey.Length,
                    hPtr, hash.Length, hPtr, hash.Length);
            }
            connectionState.WriteHandshake(ref writer, HandshakeType.finished, (buffer, state) =>
            {
                buffer.Write(hash);
                return buffer;
            });
        }
    }
}
