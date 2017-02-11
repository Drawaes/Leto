using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Certificates;
using Leto.Tls13.Handshake;
using Leto.Tls13.Hash;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.Sessions;
using Microsoft.Extensions.Logging;

namespace Leto.Tls13.State
{
    public abstract class AbstractServerState : IConnectionState
    {
        private SecurePipeListener _listener;
        private StateType _state;
        protected ILogger _logger;
        private Signal _dataForCurrentScheduleSent = new Signal(Signal.ContinuationMode.Synchronous);
        
        public AbstractServerState(SecurePipeListener listener)
        {
            _state = StateType.None;
            _listener = listener;
        }

        public ICertificate Certificate { get; set; }
        public bool SecureRenegotiation { get; set; }
        public CipherSuite CipherSuite { get; set; }
        public CryptoProvider CryptoProvider => _listener.CryptoProvider;
        public Signal DataForCurrentScheduleSent => _dataForCurrentScheduleSent;
        public IHashInstance HandshakeHash { get; set; }
        public IKeyshareInstance KeyShare { get; set; }
        public SignatureScheme SignatureScheme { get; set; }
        public SecurePipeListener Listener => _listener;
        public CertificateList CertificateList => _listener.CertificateList;
        public virtual IBulkCipherInstance ReadKey { get;}
        public ResumptionProvider ResumptionProvider => _listener.ResumptionProvider;
        public string ServerName { get;set;}
        public StateType State => _state;
        public abstract TlsVersion Version { get; }
        public virtual IBulkCipherInstance WriteKey {get; }
        public abstract ushort TlsRecordVersion { get; }
        public ILogger Logger => _logger;

        public abstract void HandleAlertMessage(ReadableBuffer readable);
        public abstract Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipeWriter pipe);
        public void StartHandshake(ref WritableBuffer writer)
        {

        }
        public void ChangeState(StateType newState)
        {
            _logger?.LogTrace("Changing to handshake from {oldState} to {newState} state", _state, newState);
            _state = newState;
        }
        public abstract void SetClientRandom(ReadableBuffer readableBuffer);
        public abstract void SetServerRandom(Memory<byte> readableBuffer);
        public abstract void Dispose();
        public abstract void HandleChangeCipherSpec(ReadableBuffer readable);
    }
}
