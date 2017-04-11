using System;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System.IO.Pipelines;
using Leto.KeyExchanges;
using Leto.Sessions;
using Leto.Internal;
using Leto.RecordLayer;
using Leto.ConnectionStates.SecretSchedules;

namespace Leto.ConnectionStates
{
    public sealed class Server13ConnectionState : ConnectionState, IConnectionState
    {
        private PskExchangeMode _pskMode = PskExchangeMode.none;
        private SecretSchedule13 _secretSchedule;

        public Server13ConnectionState(SecurePipeConnection secureConnection) : base(secureConnection)
        {
        }

        public TlsVersion RecordVersion => TlsVersion.Tls1;
        public int PskIdentity { get; set; } = -1;

        public void ChangeCipherSpec() => Alerts.AlertException.ThrowUnexpectedMessage(RecordType.ChangeCipherSpec);

        public bool HandleClientHello(ref ClientHelloParser clientHello)
        {
            CipherSuite = _cryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls13Draft18, clientHello.CipherSuites);
            HandshakeHash = _cryptoProvider.HashProvider.GetHash(CipherSuite.HashType);
            HandshakeHash.HashData(clientHello.OriginalMessage);
            ParseExtensions(ref clientHello);

            if (KeyExchange.HasPeerKey)
            {
                _secretSchedule = new SecretSchedule13(this, new Span<byte>());
                SendServerFirstFlight();
            }
            else
            {
                SendHelloRetry();
            }
            ProcessHandshake();
            return true;
        }

        public bool ProcessHandshake()
        {
            var hasWritten = false;
            var hasReader = SecureConnection.HandshakeInput.Reader.TryRead(out ReadResult reader);
            if (!hasReader) return hasWritten;
            var buffer = reader.Buffer;
            try
            {
                while (HandshakeFraming.ReadHandshakeFrame(ref buffer, out ReadableBuffer messageBuffer, out HandshakeType messageType))
                {
                    switch (messageType)
                    {
                        case HandshakeType.client_hello when _state == HandshakeState.WaitingHelloRetry:
                            var clientParser = new ClientHelloParser(messageBuffer);
                            HandshakeHash.HashData(messageBuffer);
                            ParseExtensions(ref clientParser);
                            if (!KeyExchange?.HasPeerKey == true)
                            {
                                Alerts.AlertException.ThrowFailedHandshake("Unable to negotiate a common exchange");
                            }
                            SendServerFirstFlight();
                            return true;
                        case HandshakeType.finished when _state == HandshakeState.WaitingForClientFinished:
                            var message = messageBuffer.ToSpan();
                            message = message.Slice(HandshakeFraming.HeaderSize);
                            if (_secretSchedule.ProcessClientFinished(message))
                            {
                                _state = HandshakeState.HandshakeCompleted;
                            }
                            _writeKey.Dispose();
                            _readKey.Dispose();
                            (_readKey, _writeKey) = _secretSchedule.GenerateApplicationKeys();
                            break;
                        default:
                            throw new NotImplementedException();
                    }
                }
            }
            finally
            {
                SecureConnection.HandshakeInput.Reader.Advance(buffer.Start, buffer.End);
            }
            return hasWritten;
        }

        private void SendServerFirstFlight()
        {
            HandshakeFraming.WriteHandshakeFrame(this, WriteServerHelloContent, HandshakeType.server_hello);
            SecureConnection.RecordHandler.WriteHandshakeRecords();
            SecureConnection.RecordHandler = new Tls13RecordHandler(SecureConnection);
            (_readKey, _writeKey) = _secretSchedule.GenerateHandshakeKeys();
            SecureConnection.RecordHandler = new Tls13RecordHandler(SecureConnection);
            HandshakeFraming.WriteHandshakeFrame(this, WriteEncryptedExtensions, HandshakeType.encrypted_extensions);
            HandshakeFraming.WriteHandshakeFrame(this, WriteCertificates, HandshakeType.certificate);
            HandshakeFraming.WriteHandshakeFrame(this, SendCertificateVerify, HandshakeType.certificate_verify);
            HandshakeFraming.WriteHandshakeFrame(this, ServerFinished, HandshakeType.finished);
            SecureConnection.RecordHandler.WriteHandshakeRecords();
            _state = HandshakeState.WaitingForClientFinished;
        }

        private void WriteCertificates(ref WritableBuffer buffer)
        {
            buffer.WriteBigEndian<byte>(0);
            buffer = CertificateWriter.WriteCertificates(buffer, _certificate, true);
        }

        private void WriteEncryptedExtensions(ref WritableBuffer writer) => writer.WriteBigEndian<ushort>(0);

        public unsafe void SendCertificateVerify(ref WritableBuffer writer)
        {
            writer.WriteBigEndian(_signatureScheme);
            var bookMark = writer.Buffer;
            writer.WriteBigEndian((ushort)0);
            var hash = new byte[HandshakeHash.HashSize + TlsConstants.Tls13.SignatureDigestPrefix.Length +
                TlsConstants.Tls13.Label_ServerCertificateVerify.Length];
            TlsConstants.Tls13.SignatureDigestPrefix.CopyTo(hash, 0);
            TlsConstants.Tls13.Label_ServerCertificateVerify.CopyTo(hash, TlsConstants.Tls13.SignatureDigestPrefix.Length);
            fixed (byte* hPtr = hash)
            {
                var sigPtr = hPtr + TlsConstants.Tls13.SignatureDigestPrefix.Length + TlsConstants.Tls13.Label_ServerCertificateVerify.Length;
                HandshakeHash.InterimHash(new Span<byte>(sigPtr, HandshakeHash.HashSize));
                writer.Ensure(_certificate.SignatureSize);
                var sigSize = _certificate.SignHash(_cryptoProvider.HashProvider, _signatureScheme, hash, writer.Buffer.Span);
                writer.Advance(sigSize);
                (new BigEndianAdvancingSpan(bookMark.Span)).Write((ushort)sigSize);
            }
        }

        private void WriteServerHelloContent(ref WritableBuffer writer)
        {
            var fixedSize = TlsConstants.RandomLength + sizeof(TlsVersion) + sizeof(ushort);
            writer.Ensure(fixedSize);
            var span = new BigEndianAdvancingSpan(writer.Buffer.Span);
            span.Write(TlsVersion.Tls13Draft18);
            SecureConnection.Listener.CryptoProvider.FillWithRandom(span.TakeSlice(TlsConstants.RandomLength).ToSpan());
            span.Write(CipherSuite.Code);
            writer.Advance(fixedSize);
            BufferExtensions.WriteVector<ushort>(ref writer, WriteServerHelloExtensions);
        }

        private void WriteServerHelloExtensions(ref WritableBuffer writer)
        {
            if (PskIdentity != -1)
            {
                writer.WriteBigEndian(ExtensionType.pre_shared_key);
                writer.WriteBigEndian<ushort>(sizeof(ushort));
                writer.WriteBigEndian((ushort)PskIdentity);
            }
            WriteServerKeyshare(ref writer, new IKeyExchange[] { KeyExchange });
        }

        private void WriteServerKeyshare(ref WritableBuffer writer, IKeyExchange[] keyExchanges)
        {
            writer.WriteBigEndian(ExtensionType.key_share);
            BufferExtensions.WriteVector<ushort>(ref writer, (ref WritableBuffer w) =>
            {
                foreach (var ks in keyExchanges)
                {
                    WriteKeyShare(ref w, ks);
                }
            });
        }

        public unsafe void ServerFinished(ref WritableBuffer writer)
        {
            var hashSize = _cryptoProvider.HashProvider.HashSize(CipherSuite.HashType);
            writer.Ensure(hashSize);
            _secretSchedule.GenerateServerFinished(writer.Buffer.Span.Slice(0, hashSize));
            writer.Advance(hashSize);
        }

        public static void WriteKeyShare(ref WritableBuffer writer, IKeyExchange keyshare)
        {
            writer.WriteBigEndian(keyshare.NamedGroup);
            writer.WriteBigEndian((ushort)keyshare.KeyExchangeSize);
            writer.Ensure(keyshare.KeyExchangeSize);
            writer.Advance(keyshare.WritePublicKey(writer.Buffer.Span));
        }

        public void WriteRetryKeyshare(ref WritableBuffer buffer)
        {
            buffer.WriteBigEndian(ExtensionType.key_share);
            buffer.WriteBigEndian((ushort)sizeof(NamedGroup));
            buffer.WriteBigEndian(KeyExchange.NamedGroup);
        }

        private void ProcessPskMode(BigEndianAdvancingSpan buffer)
        {
            while (buffer.Length > 0)
            {
                var mode = buffer.Read<PskExchangeMode>();
                if (_pskMode == PskExchangeMode.none)
                {
                    _pskMode = mode;
                }
                else
                {
                    _pskMode |= mode;
                }
            }
        }

        private void SendHelloRetry()
        {
            this.WriteHandshakeFrame((ref WritableBuffer w) =>
            {
                if (_state == HandshakeState.WaitingHelloRetry)
                {
                    Alerts.AlertException.ThrowUnexpectedMessage(HandshakeType.client_hello);
                }
                w.WriteBigEndian(TlsVersion.Tls13Draft18);
                BufferExtensions.WriteVector<ushort>(ref w, WriteRetryKeyshare);
            }, HandshakeType.hello_retry_request);
            _state = HandshakeState.WaitingHelloRetry;
            SecureConnection.RecordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        protected override void HandleExtension(ExtensionType extensionType, BigEndianAdvancingSpan buffer)
        {
            switch (extensionType)
            {
                case ExtensionType.supported_groups:
                    KeyExchange = KeyExchange ?? _cryptoProvider.KeyExchangeProvider.GetKeyExchangeFromSupportedGroups(buffer);
                    break;
                case ExtensionType.key_share:
                    if (KeyExchange?.HasPeerKey == true) return;
                    KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchange(buffer) ?? KeyExchange;
                    break;
                case ExtensionType.SessionTicket:
                    break;
                case ExtensionType.psk_key_exchange_modes:
                    ProcessPskMode(buffer);
                    break;
                default:
                    throw new NotSupportedException();
            }
        }

        protected override void Dispose(bool disposing) => base.Dispose(disposing);
    }
}
