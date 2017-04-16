using Leto.BulkCiphers;
using Leto.Certificates;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Handshake.Extensions;
using Leto.Hashes;
using Leto.KeyExchanges;
using Leto.RecordLayer;
using System;
using System.Collections.Generic;
using System.Text;
using Leto.Internal;
using System.IO.Pipelines;

namespace Leto.ConnectionStates
{
    public abstract class ConnectionState : IDisposable
    {
        protected AeadBulkCipher _readKey;
        protected AeadBulkCipher _writeKey;
        protected RecordHandler _recordHandler;
        protected ICryptoProvider _cryptoProvider;
        protected bool _secureRenegotiation;
        protected HandshakeState _state;
        protected ICertificate _certificate;
        protected SignatureScheme _signatureScheme;
        protected ApplicationLayerProtocolType _negotiatedAlpn;
        protected string _hostName;
        private SecurePipeConnection _secureConnection;

        public ConnectionState(SecurePipeConnection secureConnection)
        {
            _secureConnection = secureConnection;
            _recordHandler = _secureConnection.RecordHandler;
            _cryptoProvider = _secureConnection.Listener.CryptoProvider;
        }

        public SecurePipeConnection SecureConnection => _secureConnection;
        public AeadBulkCipher ReadKey => _readKey;
        public AeadBulkCipher WriteKey => _writeKey;
        public IHash HandshakeHash { get; set; }
        public CipherSuite CipherSuite { get; set; }
        public IKeyExchange KeyExchange { get; internal set; }
        public bool HandshakeComplete => _state == HandshakeState.HandshakeCompleted;

        protected void ParseExtensions(ref ClientHelloParser clientHello)
        {
            foreach (var (extensionType, buffer) in clientHello.Extensions)
            {
                switch (extensionType)
                {
                    case ExtensionType.application_layer_protocol_negotiation:
                        _negotiatedAlpn = SecureConnection.Listener.AlpnProvider.ProcessExtension(buffer);
                        break;
                    case ExtensionType.renegotiation_info:
                        SecureConnection.Listener.SecureRenegotiationProvider.ProcessExtension(buffer);
                        _secureRenegotiation = true;
                        break;
                    case ExtensionType.server_name:
                        _hostName = SecureConnection.Listener.HostNameProvider.ProcessHostNameExtension(buffer);
                        break;
                    case ExtensionType.signature_algorithms:
                        if (_certificate == null)
                        {
                            (_certificate, _signatureScheme) = SecureConnection.Listener.CertificateList.GetCertificate(buffer);
                        }
                        else
                        {
                            _signatureScheme = _certificate.SelectAlgorithm(buffer);
                        }
                        break;
                    case ExtensionType.supported_versions:
                        break;
                    default:
                        HandleExtension(extensionType, buffer);
                        break;
                }
            }
        }

        protected abstract void HandleExtension(ExtensionType extensionType, BigEndianAdvancingSpan buffer);

        protected virtual void Dispose(bool disposing)
        {
            try
            {
                HandshakeHash?.Dispose();
                HandshakeHash = null;
                _writeKey?.Dispose();
                _writeKey = null;
                _readKey?.Dispose();
                _readKey = null;
                GC.SuppressFinalize(this);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception disposing key {ex}");
                throw;
            }
        }

        public void Dispose() => Dispose(true);
        ~ConnectionState() => Dispose(false);
    }
}
