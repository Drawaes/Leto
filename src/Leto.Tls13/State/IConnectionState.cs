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
    public interface IConnectionState : IDisposable
    {
        IBulkCipherInstance ReadKey { get; }
        IBulkCipherInstance WriteKey { get; }
        StateType State { get; }
        TlsVersion Version { get; }
        Signal DataForCurrentScheduleSent { get; }
        CryptoProvider CryptoProvider { get; }
        IKeyshareInstance KeyShare { get; set; }
        CipherSuite CipherSuite { get; set; }
        IHashInstance HandshakeHash { get; set; }
        void StartHandshake(ref WritableBuffer writer);
        void HandleAlertMessage(ReadableBuffer readable);
        Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe);
    }
}
