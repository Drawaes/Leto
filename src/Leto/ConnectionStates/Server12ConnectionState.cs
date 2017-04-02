using System;
using System.IO.Pipelines;
using Leto.Handshake;
using Leto.RecordLayer;
using Leto.CipherSuites;
using Leto.Handshake.Extensions;
using Leto.KeyExchanges;
using Leto.Hashes;
using System.Threading.Tasks;
using Leto.Certificates;
using Leto.BulkCiphers;
using Leto.ConnectionStates.SecretSchedules;
using System.Binary;

namespace Leto.ConnectionStates
{
    public sealed partial class Server12ConnectionState : ConnectionState, IConnectionState
    {
        private ApplicationLayerProtocolType _negotiatedAlpn;
        private bool _secureRenegotiation;
        private SignatureScheme _signatureScheme;
        private SecretSchedule12 _secretSchedule;
        private AeadBulkCipher _storedKey;
        private bool _requiresTicket;
        private bool _abbreviatedHandshake;

        public Server12ConnectionState(SecurePipeConnection secureConnection)
            : base(secureConnection)
        {
            _secretSchedule = new SecretSchedule12(this);
        }

        public IKeyExchange KeyExchange { get; internal set; }
        public TlsVersion RecordVersion => TlsVersion.Tls12;

        public void ChangeCipherSpec()
        {
            if (_state == HandshakeState.WaitingForChangeCipherSpec)
            {
                (_readKey, _storedKey) = _secretSchedule.GenerateKeys();
                _state = HandshakeState.WaitingForClientFinished;
                return;
            }
            if (_state == HandshakeState.WaitingForClientFinishedAbbreviated)
            {
                _readKey = _storedKey;
                return;
            }
            Alerts.AlertException.ThrowUnexpectedMessage(RecordType.ChangeCipherSpec);
        }

        public WritableBufferAwaitable HandleClientHello(ref ClientHelloParser clientHello)
        {
            CipherSuite = _cryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls12, clientHello.CipherSuites);
            HandshakeHash = _cryptoProvider.HashProvider.GetHash(CipherSuite.HashType);
            HandshakeHash.HashData(clientHello.OriginalMessage);
            _certificate = SecureConnection.Listener.CertificateList.GetCertificate(null, CipherSuite.CertificateType.Value);
            _secretSchedule.SetClientRandom(clientHello.ClientRandom);
            ParseExtensions(ref clientHello);
            WritableBufferAwaitable awaiter;
            if (_abbreviatedHandshake)
            {
                awaiter = SendFirstFlightAbbreviated(clientHello);
            }
            else
            {
                awaiter = SendFirstFlightFull();
            }
            var ignore = ReadingLoop();
            return awaiter;
        }

        private async Task ReadingLoop()
        {
            while (true)
            {
                var reader = await SecureConnection.HandshakeInput.Reader.ReadAsync();
                var buffer = reader.Buffer;
                WritableBuffer writer;
                try
                {
                    while (HandshakeFraming.ReadHandshakeFrame(ref buffer, out ReadableBuffer messageBuffer, out HandshakeType messageType))
                    {
                        Span<byte> span;
                        switch (messageType)
                        {
                            case HandshakeType.client_key_exchange when _state == HandshakeState.WaitingForClientKeyExchange:
                                span = messageBuffer.ToSpan();
                                HandshakeHash.HashData(span);
                                span = span.Slice(HandshakeFraming.HeaderSize);
                                KeyExchange.SetPeerKey(span, _certificate, _signatureScheme);
                                _secretSchedule.GenerateMasterSecret();
                                _state = HandshakeState.WaitingForChangeCipherSpec;
                                break;
                            case HandshakeType.finished when _state == HandshakeState.WaitingForClientFinished:
                                span = messageBuffer.ToSpan();
                                if (_secretSchedule.GenerateAndCompareClientVerify(span))
                                {
                                    _state = HandshakeState.HandshakeCompleted;
                                }
                                if (_requiresTicket)
                                {
                                    writer = SecureConnection.HandshakeOutput.Writer.Alloc();
                                    _secretSchedule.WriteSessionTicket(ref writer);
                                    writer.Commit();
                                    _recordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
                                }
                                WriteChangeCipherSpec();
                                _writeKey = _storedKey;
                                writer = SecureConnection.HandshakeOutput.Writer.Alloc();
                                _secretSchedule.GenerateAndWriteServerVerify(ref writer);
                                writer.Commit();
                                await _recordHandler.WriteRecordsAndFlush(SecureConnection.HandshakeOutput.Reader, RecordType.Handshake);
                                _secretSchedule.DisposeStore();
                                break;
                            case HandshakeType.finished when _state == HandshakeState.WaitingForClientFinishedAbbreviated:
                                span = messageBuffer.ToSpan();
                                if (_secretSchedule.GenerateAndCompareClientVerify(span))
                                {
                                }
                                _state = HandshakeState.HandshakeCompleted;
                                _secretSchedule.DisposeStore();
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
            }
        }

        private void WriteChangeCipherSpec()
        {
            var writer = SecureConnection.HandshakeOutput.Writer.Alloc();
            writer.WriteBigEndian<byte>(1);
            writer.Commit();
            _recordHandler.WriteRecords(SecureConnection.HandshakeOutput.Reader, RecordType.ChangeCipherSpec);
        }

        private void ParseExtensions(ref ClientHelloParser clientHello)
        {
            foreach (var (extensionType, buffer) in clientHello.Extensions)
            {
                switch (extensionType)
                {
                    case ExtensionType.application_layer_protocol_negotiation:
                        _negotiatedAlpn = SecureConnection.Listener.AlpnProvider.ProcessExtension(buffer);
                        break;
                    case ExtensionType.supported_groups:
                        KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchange(CipherSuite.KeyExchange, buffer);
                        break;
                    case ExtensionType.signature_algorithms:
                        _signatureScheme = _certificate.SelectAlgorithm(buffer);
                        break;
                    case ExtensionType.renegotiation_info:
                        SecureConnection.Listener.SecureRenegotiationProvider.ProcessExtension(buffer);
                        _secureRenegotiation = true;
                        break;
                    case ExtensionType.SessionTicket:
                        ProcessSessionTicket(buffer);
                        break;
                    case ExtensionType.server_name:
                    case ExtensionType.supported_versions:
                    case ExtensionType.key_share:
                        break;
                    default:
                        throw new NotImplementedException();
                }
            }
        }

        private void ProcessSessionTicket(Span<byte> buffer)
        {
            _requiresTicket = true;
            if (buffer.Length == 0 || !_secretSchedule.ReadSessionTicket(buffer))
            {
                return;
            }
            _abbreviatedHandshake = true;
        }

        protected override void Dispose(bool disposing)
        {
            KeyExchange?.Dispose();
            KeyExchange = null;
            base.Dispose(disposing);
        }
    }
}
