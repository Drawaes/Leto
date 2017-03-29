using Leto.Handshake;
using Leto.KeyExchanges;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;

namespace Leto.ConnectionStates
{
    public sealed partial class Server12ConnectionState
    {
        private void SendFirstFlight(ref WritableBuffer writer)
        {
            WriteServerHello(ref writer, new Span<byte>());
            WriteCertificates(ref writer);
            WriteServerKeyExchange(ref writer);
            WriteServerHelloDone(ref writer);
        }

        private void WriteServerHelloDone(ref WritableBuffer writer)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, HandshakeHash, (buffer) => buffer, HandshakeType.server_hello_done);
        }

        private void WriteCertificates(ref WritableBuffer writer)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, HandshakeHash, (buffer) =>
            {
                return CertificateWriter.WriteCertificates(buffer, _certificate);
            }, HandshakeType.certificate);
        }

        private void WriteServerKeyExchange(ref WritableBuffer writer)
        {
            if (KeyExchange.RequiresServerKeyExchange)
            {
                HandshakeFraming.WriteHandshakeFrame(ref writer, HandshakeHash,
                    (buffer) => SendKeyExchange(buffer), HandshakeType.server_key_exchange);
            }
        }

        private void WriteServerHello(ref WritableBuffer writer, Span<byte> sessionId)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, HandshakeHash, (buffer) =>
            {
                return WriteServerContent(buffer, this, sessionId);
            }, HandshakeType.server_hello);
        }

        private WritableBuffer WriteServerContent(WritableBuffer writer, Server12ConnectionState state, Span<byte> sessionId)
        {
            var fixedSize = TlsConstants.RandomLength + sizeof(TlsVersion) + 2 * sizeof(byte) + sizeof(ushort) + sessionId.Length;
            writer.Ensure(fixedSize);
            var span = writer.Buffer.Span;
            span = span.WriteBigEndian(TlsVersion.Tls12);
            _secretSchedule.ServerRandom.CopyTo(span);
            span = span.Slice(_secretSchedule.ServerRandom.Length);

            //We don't support session id's instead resumption is supported through tickets
            //If we are using a ticket the client will want us to respond with the same id
            span = span.WriteBigEndian((byte)sessionId.Length);
            sessionId.CopyTo(span);
            span = span.Slice(sessionId.Length);

            span = span.WriteBigEndian(state.CipherSuite.Code);
            //We don't support compression at the TLS level as it is prone to attacks
            span = span.WriteBigEndian<byte>(0);

            writer.Advance(fixedSize);
            //Completed the fixed section now we write the extensions
            BufferExtensions.WriteVector<ushort>(ref writer, w =>
            {
                WriteExtensions(ref w);
                return w;
            });
            return writer;
        }

        public void WriteExtensions(ref WritableBuffer writer)
        {
            if (_secureRenegotiation)
            {
                _secureConnection.Listener.SecureRenegotiationProvider.WriteExtension(ref writer);
            }
            if (_negotiatedAlpn != Handshake.Extensions.ApplicationLayerProtocolType.None)
            {
                _secureConnection.Listener.AlpnProvider.WriteExtension(ref writer, _negotiatedAlpn);
            }
            if (_requiresTicket)
            {
                writer.WriteBigEndian(ExtensionType.SessionTicket);
                writer.WriteBigEndian((ushort)0);
            }
        }

        private WritableBuffer SendKeyExchange(WritableBuffer writer)
        {
            var keyExchange = KeyExchange;
            var messageLength = 4 + KeyExchange.KeyExchangeSize;
            writer.Ensure(messageLength);
            var bookMark = writer.Buffer;
            writer.WriteBigEndian(ECCurveType.named_curve);
            writer.WriteBigEndian(KeyExchange.NamedGroup);
            writer.WriteBigEndian((byte)KeyExchange.KeyExchangeSize);
            var keysWritten = KeyExchange.WritePublicKey(writer.Buffer.Span);
            writer.Advance(keysWritten);
            writer.WriteBigEndian(_signatureScheme);
            BufferExtensions.WriteVector<ushort>(ref writer, (w) =>
            {
                WriteKeySignature(ref w, bookMark.Span.Slice(0, messageLength));
                return w;
            });
            return writer;
        }

        private void WriteKeySignature(ref WritableBuffer writer, Span<byte> message)
        {
            var tempBuffer = new byte[TlsConstants.RandomLength * 2 + message.Length];
            _secretSchedule.ClientRandom.CopyTo(tempBuffer);
            _secretSchedule.ServerRandom.CopyTo(tempBuffer.Slice(TlsConstants.RandomLength));
            message.CopyTo(tempBuffer.Slice(TlsConstants.RandomLength * 2));
            writer.Ensure(_certificate.SignatureSize);
            var bytesWritten = _certificate.SignHash(_secureConnection.Listener.CryptoProvider.HashProvider,
                _signatureScheme, tempBuffer, writer.Buffer.Span);
            writer.Advance(bytesWritten);
        }
    }
}
