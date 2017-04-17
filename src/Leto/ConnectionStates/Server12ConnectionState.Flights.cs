using Leto.Handshake;
using Leto.KeyExchanges;
using Leto.RecordLayer;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Threading.Tasks;
using Leto.Internal;

namespace Leto.ConnectionStates
{
    public sealed partial class Server12ConnectionState
    {
        private void SendFirstFlightAbbreviated(ClientHelloParser clientHello)
        {
            WriteServerHello(clientHello.SessionId);
            _secretSchedule.WriteSessionTicket();
            RecordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
            _requiresTicket = false;
            WriteChangeCipherSpec();
            (_storedKey, _writeKey) = _secretSchedule.GenerateKeys();
            _secretSchedule.GenerateAndWriteServerVerify();
            _state = HandshakeState.WaitingForClientFinishedAbbreviated;
            RecordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        private void SendFirstFlightFull()
        {
            if (KeyExchange == null)
            {
                KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchange(CipherSuite.KeyExchange, default(BigEndianAdvancingSpan));
            }
            SendSecondFlight();
            _state = HandshakeState.WaitingForClientKeyExchange;
            RecordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        private void SendSecondFlight()
        {
            WriteServerHello(new Span<byte>());
            WriteCertificates();
            WriteServerKeyExchange();
            WriteServerHelloDone();
        }

        private void WriteServerHelloDone() =>
            this.WriteHandshakeFrame((ref WritableBuffer buffer) => { return; }, HandshakeType.server_hello_done);
        
        private void WriteServerKeyExchange()
        {
            if (KeyExchange.RequiresServerKeyExchange)
            {
                this.WriteHandshakeFrame(SendKeyExchange, HandshakeType.server_key_exchange);
            }
        }

        private void WriteServerHello(Span<byte> sessionId) =>
            this.WriteHandshakeFrame((ref WritableBuffer buffer) => WriteServerContent(ref buffer, sessionId), HandshakeType.server_hello);

        private void WriteServerContent(ref WritableBuffer writer, Span<byte> sessionId)
        {
            var fixedSize = TlsConstants.RandomLength + sizeof(TlsVersion) + 2 * sizeof(byte) + sizeof(ushort) + sessionId.Length;
            writer.Ensure(fixedSize);
            var span = new BigEndianAdvancingSpan(writer.Buffer.Span);
            span.Write(TlsVersion.Tls12);
            span.CopyFrom(_secretSchedule.ServerRandom);

            //We don't support session id's instead resumption is supported through tickets
            //If we are using a ticket the client will want us to respond with the same id
            span.Write((byte)sessionId.Length);
            span.CopyFrom(sessionId);

            span.Write(CipherSuite.Code);
            //We don't support compression at the TLS level as it is prone to attacks
            span.Write<byte>(0);

            writer.Advance(fixedSize);
            //Completed the fixed section now we write the extensions
            BufferExtensions.WriteVector<ushort>(ref writer, WriteExtensions);
        }

        public void WriteExtensions(ref WritableBuffer writer)
        {
            if (_secureRenegotiation)
            {
                SecureConnection.Listener.SecureRenegotiationProvider.WriteExtension(ref writer);
            }
            if (_negotiatedAlpn != Handshake.Extensions.ApplicationLayerProtocolType.None)
            {
                SecureConnection.Listener.AlpnProvider.WriteExtension(ref writer, _negotiatedAlpn);
            }
            if (_requiresTicket)
            {
                writer.WriteBigEndian(ExtensionType.SessionTicket);
                writer.WriteBigEndian((ushort)0);
            }
        }

        private void SendKeyExchange(ref WritableBuffer writer)
        {
            var keyExchange = KeyExchange;
            var messageLength = 4 + KeyExchange.KeyExchangeSize;
            writer.Ensure(messageLength);
            var bookMark = writer.Buffer;
            writer.WriteBigEndian(ECCurveType.named_curve);
            writer.WriteBigEndian(KeyExchange.NamedGroup);
            writer.WriteBigEndian((byte)KeyExchange.KeyExchangeSize);
            var keybytesWritten = KeyExchange.WritePublicKey(writer.Buffer.Span);
            writer.Advance(keybytesWritten);
            writer.WriteBigEndian(_signatureScheme);
            BufferExtensions.WriteVector<ushort>(ref writer, (ref WritableBuffer w) =>
            {
                var span = bookMark.Span.Slice(0, messageLength);
                WriteKeySignature(ref w, span);
            });
        }

        private void WriteKeySignature(ref WritableBuffer writer, Span<byte> message)
        {
            var tempBuffer = new byte[TlsConstants.RandomLength * 2 + message.Length];
            _secretSchedule.ClientRandom.CopyTo(tempBuffer);
            _secretSchedule.ServerRandom.CopyTo(tempBuffer.Slice(TlsConstants.RandomLength));
            message.CopyTo(tempBuffer.Slice(TlsConstants.RandomLength * 2));
            writer.Ensure(_certificate.SignatureSize);
            var bytesWritten = _certificate.SignHash(_cryptoProvider.HashProvider,
                _signatureScheme, tempBuffer, writer.Buffer.Span);
            writer.Advance(bytesWritten);
        }
    }
}
