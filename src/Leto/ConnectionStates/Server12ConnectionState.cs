using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Handshake;
using Leto.RecordLayer;
using Leto.CipherSuites;
using Leto.Handshake.Extensions;
using Leto.Keyshares;
using Leto.Hashes;
using System.Threading.Tasks;
using Leto.Certificates;

namespace Leto.ConnectionStates
{
    public sealed partial class Server12ConnectionState : IConnectionState
    {
        private CipherSuite _cipherSuite;
        private SecurePipeConnection _secureConnection;
        private ApplicationLayerProtocolType _negotiatedAlpn;
        private bool _secureRenegotiation;
        private IHash _handshakeHash;
        private ICertificate _certificate;
        private SignatureScheme _signatureScheme;
        private HandshakeState _state;
        private SecretSchedules.SecretSchedule12 _secretSchedule;

        public Server12ConnectionState(SecurePipeConnection secureConnection)
        {
            _secureConnection = secureConnection;
            _secretSchedule = new SecretSchedules.SecretSchedule12(this);
        }

        public CipherSuite CipherSuite => _cipherSuite;
        public ApplicationLayerProtocolType NegotiatedAlpn => _negotiatedAlpn;
        internal bool SecureRenegotiationSupported => _secureRenegotiation;
        internal SecurePipeConnection SecureConnection => _secureConnection;
        internal IKeyshare Keyshare { get; set; }
        public IHash HandshakeHash => _handshakeHash;
        public ushort RecordVersion => (ushort)TlsVersion.Tls12;
        public SignatureScheme SignatureScheme => _signatureScheme;

        public Task HandleHandshakeRecord(ReadableBuffer record)
        {
            throw new NotImplementedException();
        }

        public void ChangeCipherSpec()
        {
            if (_state != HandshakeState.WaitingForChangeCipherSpec)
            {
                Alerts.AlertException.ThrowUnexpectedMessage(RecordType.ChangeCipherSpec);
            }
        }

        public async Task HandleClientHello(ClientHelloParser clientHello)
        {
            _secretSchedule.SetClientRandom(clientHello.ClientRandom);
            _cipherSuite = _secureConnection.Listener.CryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls12, clientHello.CipherSuites);
            _certificate = _secureConnection.Listener.CertificateList.GetCertificate(null, _cipherSuite.CertificateType.Value);
            _handshakeHash = _secureConnection.Listener.CryptoProvider.HashProvider.GetHash(_cipherSuite.HashType);
            ParseExtensions(ref clientHello);
            if (Keyshare == null)
            {
                Keyshare = _secureConnection.Listener.CryptoProvider.KeyshareProvider.GetKeyshare(_cipherSuite.KeyExchange, default(Span<byte>));
            }
            var writer = _secureConnection.HandshakeOutput.Writer.Alloc();
            SendFirstFlight(ref writer);
            await writer.FlushAsync();
            _state = HandshakeState.WaitingForClientKeyExchange;
            var ignore = ReadingLoop();
            await _secureConnection.RecordHandler.WriteRecords(_secureConnection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        private async Task ReadingLoop()
        {
            while (true)
            {
                var reader = await _secureConnection.HandshakeInput.Reader.ReadAsync();
                var buffer = reader.Buffer;
                try
                {
                    while (HandshakeFraming.ReadHandshakeFrame(ref buffer, out ReadableBuffer messageBuffer, out HandshakeType messageType))
                    {
                        switch (messageType)
                        {
                            case HandshakeType.client_key_exchange when _state == HandshakeState.WaitingForClientKeyExchange:
                                var span = messageBuffer.ToSpan();
                                _handshakeHash.HashData(span);
                                span = span.Slice(HandshakeFraming.HeaderSize);
                                Keyshare.SetPeerKey(span, _certificate, _signatureScheme);
                                _secretSchedule.GenerateMasterSecret();
                                _state = HandshakeState.WaitingForChangeCipherSpec;
                                break;
                            default:
                                throw new NotImplementedException();
                        }
                    }
                }
                finally
                {
                    _secureConnection.HandshakeInput.Reader.Advance(buffer.Start, buffer.End);
                }
            }
        }

        private void ParseExtensions(ref ClientHelloParser clientHello)
        {
            foreach (var (extensionType, buffer) in clientHello.Extensions)
            {
                switch (extensionType)
                {
                    case ExtensionType.application_layer_protocol_negotiation:
                        _negotiatedAlpn = _secureConnection.Listener.AlpnProvider.ProcessExtension(buffer);
                        break;
                    case ExtensionType.supported_groups:
                        Keyshare = _secureConnection.Listener.CryptoProvider.KeyshareProvider.GetKeyshare(_cipherSuite.KeyExchange, buffer);
                        break;
                    case ExtensionType.signature_algorithms:
                        _signatureScheme = _certificate.SelectAlgorithm(buffer);
                        break;
                    case ExtensionType.renegotiation_info:
                        _secureConnection.Listener.SecureRenegotiationProvider.ProcessExtension(buffer);
                        _secureRenegotiation = true;
                        break;
                    case ExtensionType.server_name:
                        break;
                    default:
                        throw new NotImplementedException();
                }
            }
        }

        public void Dispose()
        {
            _handshakeHash?.Dispose();
            _handshakeHash = null;
            Keyshare?.Dispose();
            Keyshare = null;
        }

        ~Server12ConnectionState()
        {
            Dispose();
        }
    }
}
