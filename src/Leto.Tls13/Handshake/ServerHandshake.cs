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
            connectionState.WriteHandshake(ref writer, HandshakeType.encrypted_extensions, (buffer, state) =>
            {
                BufferExtensions.WriteVector<ushort>(ref buffer, Extensions.WriteExtensionList, state);
                return buffer;
            });
            connectionState.WriteHandshake(ref writer, HandshakeType.certificate, WriteCertificate);
            connectionState.WriteHandshake(ref writer, HandshakeType.certificate_verify, SendCertificateVerify);
        }

        public static WritableBuffer WriteCertificate(WritableBuffer writer, ConnectionState connectionState)
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

        internal unsafe static WritableBuffer SendCertificateVerify(WritableBuffer writer, ConnectionState connectionState)
        {
            var hash = new byte[connectionState.HandshakeHash.HashSize];
            Span<byte> result;
            fixed (byte* hPtr = hash)
            {
                connectionState.HandshakeHash.InterimHash(hPtr, hash.Length);
                result = connectionState.Certificate.SignHash(connectionState.CryptoProvider.HashProvider, connectionState.SignatureScheme,
                    hPtr, hash.Length);
            }

            writer.WriteBigEndian(connectionState.SignatureScheme);
            writer.WriteBigEndian((ushort)result.Length);
            writer.Write(result);
            return writer;
        }

        internal static unsafe void ServerFinished(ref WritableBuffer writer, ConnectionState connectionState, byte[] serverFinishedKey)
        {
            var hash = new byte[connectionState.HandshakeHash.HashSize];
            fixed (byte* hPtr = hash)
            fixed (byte* kPtr = serverFinishedKey)
            {
                connectionState.HandshakeHash.InterimHash(hPtr, hash.Length);
                connectionState.CryptoProvider.HashProvider.HmacData(connectionState.CipherSuite.HashType,kPtr, serverFinishedKey.Length,
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
