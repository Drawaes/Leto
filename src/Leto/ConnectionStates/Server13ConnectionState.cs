using System;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System.IO.Pipelines;
using Leto.KeyExchanges;
using Leto.Sessions;
using Leto.Internal;

namespace Leto.ConnectionStates
{
    public sealed class Server13ConnectionState : ConnectionState, IConnectionState
    {
        private PskExchangeMode _pskMode = PskExchangeMode.none;

        public Server13ConnectionState(SecurePipeConnection secureConnection) : base(secureConnection)
        {
        }

        public TlsVersion RecordVersion => TlsVersion.Tls12;
        public int PskIdentity { get; set; } = -1;

        public void ChangeCipherSpec() => Alerts.AlertException.ThrowUnexpectedMessage(RecordLayer.RecordType.ChangeCipherSpec);

        public bool HandleClientHello(ref ClientHelloParser clientHello)
        {
            CipherSuite = _cryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls13Draft18, clientHello.CipherSuites);
            HandshakeHash = _cryptoProvider.HashProvider.GetHash(CipherSuite.HashType);
            HandshakeHash.HashData(clientHello.OriginalMessage);
            ParseExtensions(ref clientHello);

            if (KeyExchange.HasPeerKey)
            {
                SendServerFirstFlight();
            }
            else
            {
                SendHelloRetry();
            }
            ProcessHandshake();
            return true;
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
            SecureConnection.RecordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordLayer.RecordType.Handshake);
        }

        private void SendServerFirstFlight() => throw new NotImplementedException();

        private WritableBuffer WriteServerHelloContent(WritableBuffer writer)
        {
            var fixedSize = TlsConstants.RandomLength + sizeof(TlsVersion) + sizeof(ushort);
            writer.Ensure(fixedSize);
            var span = new Internal.BigEndianAdvancingSpan(writer.Buffer.Span);
            span.Write(TlsVersion.Tls13Draft18);
            SecureConnection.Listener.CryptoProvider.FillWithRandom(span.TakeSlice(TlsConstants.RandomLength).ToSpan());
            span.Write(CipherSuite.Code);
            writer.Advance(fixedSize);

            BufferExtensions.WriteVector<ushort>(ref writer, WriteServerHelloExtensions);
            return writer;
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

        protected override void HandleExtension(ExtensionType extensionType, BigEndianAdvancingSpan buffer)
        {
            switch (extensionType)
            {
                case ExtensionType.supported_groups:
                    if (KeyExchange == null)
                    {
                        KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchangeFromSupportedGroups(buffer);
                    }
                    break;
                case ExtensionType.key_share:
                    if (KeyExchange?.HasPeerKey == true)
                    {
                        return;
                    }
                    KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchange(buffer) ?? KeyExchange;
                    break;
                case ExtensionType.SessionTicket:
                    break;
                case ExtensionType.psk_key_exchange_modes:
                    ProcessPskMode(buffer);
                    break;
                default:
                    throw new NotImplementedException();
            }
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

        protected override void Dispose(bool disposing) => base.Dispose(disposing);

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
                    HandshakeHash?.HashData(messageBuffer);
                    switch (messageType)
                    {
                        case HandshakeType.client_hello when _state == HandshakeState.WaitingHelloRetry:
                            var clientParser = new ClientHelloParser(messageBuffer);
                            ParseExtensions(ref clientParser);
                            if (!KeyExchange?.HasPeerKey == true)
                            {
                                Alerts.AlertException.ThrowFailedHandshake("Unable to negotiate a common exchange");
                            }
                            SendServerFirstFlight();
                            return true;
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
    }
}
