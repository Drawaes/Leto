﻿using Leto.Handshake;
using Leto.KeyExchanges;
using Leto.RecordLayer;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Threading.Tasks;

namespace Leto.ConnectionStates
{
    public sealed partial class Server12ConnectionState
    {
        private void SendFirstFlightAbbreviated(ClientHelloParser clientHello)
        {
            var writer = SecureConnection.HandshakeOutput.Writer.Alloc();
            WriteServerHello(ref writer, clientHello.SessionId);
            _secretSchedule.WriteSessionTicket(ref writer);
            writer.Commit();
            _recordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
            _requiresTicket = false;
            WriteChangeCipherSpec();
            (_storedKey, _writeKey) = _secretSchedule.GenerateKeys();
            _secretSchedule.GenerateAndWriteServerVerify();
            _state = HandshakeState.WaitingForClientFinishedAbbreviated;
            _recordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        private void SendFirstFlightFull()
        {
            if (KeyExchange == null)
            {
                KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchange(CipherSuite.KeyExchange, default(Span<byte>));
            }
            var writer = SecureConnection.HandshakeOutput.Writer.Alloc();
            SendSecondFlight(ref writer);
            writer.Commit();
            _state = HandshakeState.WaitingForClientKeyExchange;
            _recordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        private void SendSecondFlight(ref WritableBuffer writer)
        {
            WriteServerHello(ref writer, new Span<byte>());
            WriteCertificates(ref writer);
            WriteServerKeyExchange(ref writer);
            WriteServerHelloDone(ref writer);
        }

        private void WriteServerHelloDone(ref WritableBuffer writer) =>
            this.WriteHandshakeFrame((ref WritableBuffer buffer) => { return; }, HandshakeType.server_hello_done);

        private void WriteCertificates(ref WritableBuffer writer) =>
            this.WriteHandshakeFrame((ref WritableBuffer buffer) =>
                CertificateWriter.WriteCertificates(buffer, _certificate), HandshakeType.certificate);

        private void WriteServerKeyExchange(ref WritableBuffer writer)
        {
            if (KeyExchange.RequiresServerKeyExchange)
            {
                this.WriteHandshakeFrame(SendKeyExchange, HandshakeType.server_key_exchange);
            }
        }

        private void WriteServerHello(ref WritableBuffer writer, Span<byte> sessionId) =>
            this.WriteHandshakeFrame((ref WritableBuffer buffer) => WriteServerContent(ref buffer, sessionId), HandshakeType.server_hello);
        
        private void WriteServerContent(ref WritableBuffer writer, Span<byte> sessionId)
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

            span = span.WriteBigEndian(CipherSuite.Code);
            //We don't support compression at the TLS level as it is prone to attacks
            span = span.WriteBigEndian<byte>(0);

            writer.Advance(fixedSize);
            //Completed the fixed section now we write the extensions
            BufferExtensions.WriteVector<ushort>(ref writer, w =>
            {
                WriteExtensions(ref w);
                return w;
            });
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
            BufferExtensions.WriteVector<ushort>(ref writer, (w) =>
            {
                var span = bookMark.Span.Slice(0, messageLength);
                WriteKeySignature(ref w, span);
                return w;
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
