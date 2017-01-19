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

namespace Leto.Tls13.State
{
    public class ServerStateTls12 : AbstractServerState
    {
        private IBulkCipherInstance _readKey;
        private IBulkCipherInstance _writeKey;
        private byte[] _clientRandom;

        public ServerStateTls12(SecurePipelineListener listener)
            :base(listener)
        {
        }

        public override IBulkCipherInstance ReadKey => _readKey;
        public override TlsVersion Version => TlsVersion.Tls12;
        public override IBulkCipherInstance WriteKey => _writeKey;
                
        public override void SetClientRandom(ReadableBuffer readableBuffer)
        {
            if (readableBuffer.Length != Hello.RandomLength)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, "Invalid client random length");
            }
            _clientRandom = readableBuffer.ToArray();
        }

        public override void HandleAlertMessage(ReadableBuffer messageBuffer)
        {
            var level = messageBuffer.ReadBigEndian<Alerts.AlertLevel>();
            messageBuffer = messageBuffer.Slice(sizeof(Alerts.AlertLevel));
            var description = messageBuffer.ReadBigEndian<Alerts.AlertDescription>();
            Alerts.AlertException.ThrowAlert(level, description, "Alert from the client");
        }
        
        public override async Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe)
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
                    this.WriteHandshake(ref writer, HandshakeType.certificate, ServerHandshakeTls12.SendCertificates);
                    await writer.FlushAsync();
                    break;
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message, $"Not in any known state {State} that we expected a handshake messge from {handshakeMessageType}");
                    break;
            }
        }
        
        public override void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
