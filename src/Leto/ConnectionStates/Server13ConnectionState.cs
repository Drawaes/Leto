using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System.IO.Pipelines;
using System.Net.Http;
using Leto.KeyExchanges;
using Leto.Sessions;

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
            var span = writer.Buffer.Span;
            span = span.WriteBigEndian(TlsVersion.Tls13Draft18);
            SecureConnection.Listener.CryptoProvider.FillWithRandom(span.Slice(0, TlsConstants.RandomLength));
            span = span.Slice(TlsConstants.RandomLength);
            span = span.WriteBigEndian(CipherSuite.Code);
            writer.Advance(fixedSize);

            BufferExtensions.WriteVector<ushort>(ref writer, WriteServerHelloExtensions);
            return writer;
        }

        private WritableBuffer WriteServerHelloExtensions(WritableBuffer writer)
        {
            if (PskIdentity != -1)
            {
                writer.WriteBigEndian(ExtensionType.pre_shared_key);
                writer.WriteBigEndian<ushort>(sizeof(ushort));
                writer.WriteBigEndian((ushort)PskIdentity);
            }
            WriteServerKeyshare(ref writer, new IKeyExchange[] { KeyExchange });
            return writer;
        }

        private void WriteServerKeyshare(ref WritableBuffer writer, IKeyExchange[] keyExchanges)
        {
            writer.WriteBigEndian(ExtensionType.key_share);
            BufferExtensions.WriteVector<ushort>(ref writer, w =>
            {
                foreach (var ks in keyExchanges)
                {
                    WriteKeyShare(ref w, ks);
                }
                return w;
            });
        }

        public static void WriteKeyShare(ref WritableBuffer writer, IKeyExchange keyshare)
        {
            writer.WriteBigEndian(keyshare.NamedGroup);
            writer.WriteBigEndian((ushort)keyshare.KeyExchangeSize);
            writer.Ensure(keyshare.KeyExchangeSize);
            writer.Advance(keyshare.WritePublicKey(writer.Buffer.Span));
        }

        public WritableBuffer WriteRetryKeyshare(WritableBuffer buffer)
        {
            buffer.WriteBigEndian(ExtensionType.key_share);
            buffer.WriteBigEndian((ushort)sizeof(NamedGroup));
            buffer.WriteBigEndian(KeyExchange.NamedGroup);
            return buffer;
        }

        protected override void HandleExtension(ExtensionType extensionType, Span<byte> buffer)
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

        private void ProcessPskMode(Span<byte> buffer)
        {
            while (buffer.Length > 0)
            {
                PskExchangeMode mode;
                (mode, buffer) = buffer.Consume<PskExchangeMode>();
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
                            if(!KeyExchange?.HasPeerKey == true)
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
