using Leto.Handshake;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;

namespace Leto.ConnectionStates
{
    public sealed partial class Server12ConnectionState
    {
        private void SendFirstFlight(ref WritableBuffer writer)
        {
            WriteServerHelloTls12(ref writer);
            WriteCertificates(ref writer);
            WriteServerKeyExchange(ref writer);
            WriteServerHelloDone(ref writer);
        }

        private void WriteServerHelloDone(ref WritableBuffer writer)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, _handshakeHash, (buffer) => buffer, HandshakeType.server_hello_done);
        }

        private void WriteCertificates(ref WritableBuffer writer)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, _handshakeHash, (buffer) =>
            {
                return CertificateWriter.WriteCertificates(buffer, _certificate);
            }, HandshakeType.certificate);
        }

        private void WriteServerKeyExchange(ref WritableBuffer writer)
        {
            if (Keyshare.RequiresServerKeyExchange)
            {
                HandshakeFraming.WriteHandshakeFrame(ref writer, _handshakeHash,
                    (buffer) => KeyExchangeWriter.SendKeyExchange(buffer, Keyshare, _signatureScheme),
                    HandshakeType.server_key_exchange);
            }
        }

        private void WriteServerHelloTls12(ref WritableBuffer writer)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, _handshakeHash, (buffer) =>
            {
                return WriteServerHello(buffer, this);
            }, HandshakeType.server_hello);
        }

        public WritableBuffer WriteServerHello(WritableBuffer writer, Server12ConnectionState state)
        {
            var fixedSize = TlsConstants.RandomLength + sizeof(TlsVersion) + 2 * sizeof(byte) + sizeof(ushort);
            writer.Ensure(fixedSize);
            var span = writer.Buffer.Span;
            span = span.WriteBigEndian(TlsVersion.Tls12);
            _secretSchedule.ServerRandom.CopyTo(span);
            span = span.Slice(_secretSchedule.ServerRandom.Length);

            //We don't support session id's instead resumption is supported through tickets
            span = span.WriteBigEndian<byte>(0);

            span = span.WriteBigEndian(state.CipherSuite.Code);
            //We don't support compression at the TLS level as it is prone to attacks
            span = span.WriteBigEndian<byte>(0);

            writer.Advance(fixedSize);
            //Completed the fixed section now we write the extensions
            WriteExtensions(ref writer);
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
        }
    }
}
