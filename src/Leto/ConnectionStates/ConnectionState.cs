using Leto.BulkCiphers;
using Leto.Certificates;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Handshake.Extensions;
using Leto.Hashes;
using Leto.KeyExchanges;
using Leto.RecordLayer;
using System;
using Leto.Internal;
using Leto.Alerts;
using System.Linq;

namespace Leto.ConnectionStates
{
    public abstract class ConnectionState : IKeyPair, IDisposable
    {
        protected AeadBulkCipher _readKey;
        protected AeadBulkCipher _writeKey;
        protected ICryptoProvider _cryptoProvider;
        protected bool _secureRenegotiation;
        protected HandshakeState _state = HandshakeState.WaitingForClientHello;
        protected ICertificate _certificate;
        protected SignatureScheme _signatureScheme;
        protected ApplicationLayerProtocolType _negotiatedAlpn;
        protected string _hostName;
        private static TlsVersion[] s_supportedVersions =
        {
            TlsVersion.Tls12,
        };
        private SecurePipeConnection _secureConnection;

        public ConnectionState(SecurePipeConnection secureConnection)
        {
            _secureConnection = secureConnection;
            _cryptoProvider = _secureConnection.Listener.CryptoProvider;
        }

        public SecurePipeConnection SecureConnection => _secureConnection;
        public AeadBulkCipher ReadKey => _readKey;
        public AeadBulkCipher WriteKey => _writeKey;
        public IHash HandshakeHash { get; set; }
        public CipherSuite CipherSuite { get; set; }
        public IKeyExchange KeyExchange { get; internal set; }
        public bool HandshakeComplete => _state == HandshakeState.HandshakeCompleted;
        internal RecordHandler RecordHandler => SecureConnection.RecordHandler;

        protected virtual void Dispose(bool disposing)
        {
            HandshakeHash?.Dispose();
            HandshakeHash = null;
            _writeKey?.Dispose();
            _writeKey = null;
            _readKey?.Dispose();
            _readKey = null;
            GC.SuppressFinalize(this);
        }

        protected TlsVersion GetVersion(ref ClientHelloParser helloParser) => MatchVersionOrThrow(helloParser.TlsVersion);

        private TlsVersion MatchVersionOrThrow(TlsVersion tlsVersion)
        {
            if (!MatchVersion(tlsVersion))
            {
                AlertException.ThrowAlert(AlertLevel.Fatal,
                    AlertDescription.protocol_version, $"Could not match {tlsVersion} to any supported version");
            }
            return tlsVersion;
        }

        protected bool MatchVersion(TlsVersion tlsVersion)
        {
            foreach (var version in s_supportedVersions)
            {
                if (version == tlsVersion)
                {
                    return true;
                }
            }
            return false;
        }

        public void Dispose() => Dispose(true);
        ~ConnectionState() => Dispose(false);
    }
}
