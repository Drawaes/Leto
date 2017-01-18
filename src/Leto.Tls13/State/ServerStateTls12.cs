using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Handshake;
using Leto.Tls13.Hash;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;

namespace Leto.Tls13.State
{
    public class ServerStateTls12 : IConnectionState
    {
        private Signal _dataForCurrentScheduleSent = new Signal(Signal.ContinuationMode.Synchronous);
        private SecurePipelineListener _listener;
        private IBulkCipherInstance _readKey;
        private IBulkCipherInstance _writeKey;
        private StateType _state;

        public ServerStateTls12(SecurePipelineListener listener)
        {
            _state = StateType.None;
            _listener = listener;
        }

        public Signal DataForCurrentScheduleSent => _dataForCurrentScheduleSent;
        public IBulkCipherInstance ReadKey => _readKey;
        public StateType State => _state;
        public TlsVersion Version => TlsVersion.Tls12;
        public IBulkCipherInstance WriteKey => _writeKey;
        public CipherSuite CipherSuite { get; set; }
        public CryptoProvider CryptoProvider => _listener.CryptoProvider;
        public IHashInstance HandshakeHash { get; set; }
        public IKeyshareInstance KeyShare { get;set;}

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void HandleAlertMessage(ReadableBuffer readable)
        {
            throw new NotImplementedException();
        }

        public async Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe)
        {
            WritableBuffer writer;
            switch (State)
            {
                case StateType.None:
                    if (handshakeMessageType != HandshakeType.client_hello)
                    {
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message, "Tls 12 didnt get a client hello");
                    }
                    Hello.ReadClientHelloTls12(buffer, this);
                    if (CipherSuite == null)
                    {
                        //Couldn't agree a set of ciphers
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Could not agree on a cipher suite during reading client hello");
                    }
                    this.StartHandshakeHash(buffer);
                    //Write server hello
                    _state = StateType.SendServerHello;
                    writer = pipe.Alloc();
                    this.WriteHandshake(ref writer, HandshakeType.server_hello, Hello.SendServerHello12);
                    //block our next actions because we need to have sent the message before changing keys
                    _dataForCurrentScheduleSent.Reset();
                    await writer.FlushAsync();
                    await _dataForCurrentScheduleSent;
                    break;
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message, $"Not in any known state {State} that we expected a handshake messge from {handshakeMessageType}");
                    break;
            }
        }

        public void StartHandshake(ref WritableBuffer writer)
        {
        }
    }
}
