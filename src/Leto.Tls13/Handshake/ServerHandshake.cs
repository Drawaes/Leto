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
        public static void SendFlightOne(ref WritableBuffer writer, IConnectionStateTls13 connectionState)
        {
            connectionState.WriteHandshake(ref writer, HandshakeType.encrypted_extensions, (buffer, state) =>
            {
                BufferExtensions.WriteVector<ushort>(ref buffer, Extensions.WriteExtensionList, state);
                return buffer;
            });
        }

        public static void SendFlightOne2(ref WritableBuffer writer, IConnectionStateTls13 connectionState)
        {
            if (connectionState.PskIdentity == -1)
            {

                connectionState.WriteHandshake(ref writer, HandshakeType.certificate, WriteCertificate);
            }
        }

        public static void SendFlightOne3(ref WritableBuffer writer, IConnectionStateTls13 connectionState)
        {
            if (connectionState.PskIdentity == -1)
            {

                connectionState.WriteHandshake(ref writer, HandshakeType.certificate_verify, SendCertificateVerify);
            }
        }

        public static WritableBuffer WriteCertificate(WritableBuffer writer, IConnectionStateTls13 connectionState)
        {
            writer.WriteBigEndian<byte>(0);
            BufferExtensions.WriteVector24Bit(ref writer, (buffer, state) =>
            {
                WriteCertificateEntry(ref buffer, state.Certificate.CertificateData);
                for (int i = 0; i < state.Certificate.CertificateChain.Length; i++)
                {
                    WriteCertificateEntry(ref buffer, state.Certificate.CertificateChain[i]);
                }
                return buffer;
            }, connectionState);
            return writer;
        }

        public static void WriteCertificateEntry(ref WritableBuffer writer, byte[] certificate)
        {
            writer.Ensure(3);
            writer.Memory.Write24BitNumber(certificate.Length);
            writer.Advance(3);
            writer.Write(certificate);
            writer.WriteBigEndian<ushort>(0);
        }

        public unsafe static WritableBuffer SendCertificateVerify(WritableBuffer writer, IConnectionStateTls13 state)
        {
            writer.WriteBigEndian(state.SignatureScheme);
            var bookMark = writer.Memory;
            writer.WriteBigEndian((ushort)0);
            var hash = new byte[state.HandshakeHash.HashSize + Tls1_3Consts.SignatureDigestPrefix.Length + Tls1_3Consts.ServerCertificateVerify.Length];
            Tls1_3Consts.SignatureDigestPrefix.CopyTo(hash, 0);
            Tls1_3Consts.ServerCertificateVerify.CopyTo(hash, Tls1_3Consts.SignatureDigestPrefix.Length);
            fixed (byte* hPtr = hash)
            {
                var sigPtr = hPtr + Tls1_3Consts.SignatureDigestPrefix.Length + Tls1_3Consts.ServerCertificateVerify.Length;
                state.HandshakeHash.InterimHash(sigPtr, state.HandshakeHash.HashSize);
                var sigSize = state.Certificate.SignHash(state.CryptoProvider.HashProvider, state.SignatureScheme, ref writer, hPtr, hash.Length);
                bookMark.Span.Write16BitNumber((ushort)sigSize);
            }
            return writer;
        }

        public static unsafe void ServerFinished(ref WritableBuffer writer, IConnectionStateTls13 connectionState, byte[] finishedKey)
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
