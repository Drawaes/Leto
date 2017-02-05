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

namespace Leto.Tls13.State
{
    public abstract class AbstractServerState : IConnectionState
    {
        private SecurePipelineListener _listener;
        protected StateType _state;
        private Signal _dataForCurrentScheduleSent = new Signal(Signal.ContinuationMode.Synchronous);
        private byte[] _clientRandom;
        private byte[] _serverRandom;

        public AbstractServerState(SecurePipelineListener listener)
        {
            _state = StateType.None;
            _listener = listener;
        }

        public ICertificate Certificate { get; set; }
        public CipherSuite CipherSuite { get; set; }
        public CryptoProvider CryptoProvider => _listener.CryptoProvider;
        public Signal DataForCurrentScheduleSent => _dataForCurrentScheduleSent;
        public IHashInstance HandshakeHash { get; set; }
        public IKeyshareInstance KeyShare { get; set; }
        public SignatureScheme SignatureScheme { get; set; }
        public SecurePipelineListener Listener => _listener;
        public CertificateList CertificateList => _listener.CertificateList;
        public virtual IBulkCipherInstance ReadKey { get;}
        public ResumptionProvider ResumptionProvider => _listener.ResumptionProvider;
        public byte[] ClientRandom => _clientRandom;
        public byte[] ServerRandom => _serverRandom;
        public string ServerName { get;set;}
        public StateType State => _state;
        public abstract TlsVersion Version { get; }
        public virtual IBulkCipherInstance WriteKey {get; }
        public abstract ushort TlsRecordVersion { get; }

        public abstract void HandleAlertMessage(ReadableBuffer readable);
        public abstract Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe);
        public void StartHandshake(ref WritableBuffer writer)
        {

        }
        public void SetClientRandom(ReadableBuffer readableBuffer)
        {
            if (readableBuffer.Length != Hello.RandomLength)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, "Invalid client random length");
            }
            _clientRandom = readableBuffer.ToArray();
        }

        public void SetServerRandom(byte[] readableBuffer)
        {
            if (readableBuffer.Length != Hello.RandomLength)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, "Invalid client random length");
            }
            _serverRandom = readableBuffer;
        }

        public abstract void Dispose();
    }
}
