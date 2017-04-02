using Leto.BulkCiphers;
using Leto.Certificates;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using Leto.RecordLayer;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.ConnectionStates
{
    public abstract class ConnectionState : IDisposable
    {
        protected AeadBulkCipher _readKey;
        protected AeadBulkCipher _writeKey;
        protected RecordHandler _recordHandler;
        protected ICryptoProvider _cryptoProvider;
        protected HandshakeState _state;
        protected ICertificate _certificate;
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
        public bool HandshakeComplete => _state == HandshakeState.HandshakeCompleted;

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            HandshakeHash?.Dispose();
            HandshakeHash = null;
            GC.SuppressFinalize(this);
        }

        ~ConnectionState()
        {
            Dispose(false);
        }
    }
}
