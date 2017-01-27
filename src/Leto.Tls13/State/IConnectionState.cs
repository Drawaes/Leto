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
    public interface IConnectionState : IDisposable
    {
        ICertificate Certificate { get; set; }
        IBulkCipherInstance ReadKey { get; }
        IBulkCipherInstance WriteKey { get; }
        StateType State { get; }
        string ServerName { get; set; }
        SignatureScheme SignatureScheme { get; set; }
        TlsVersion Version { get; }
        ResumptionProvider ResumptionProvider { get; }
        CertificateList CertificateList { get; }
        Signal DataForCurrentScheduleSent { get; }
        CryptoProvider CryptoProvider { get; }
        IKeyshareInstance KeyShare { get; set; }
        CipherSuite CipherSuite { get; set; }
        IHashInstance HandshakeHash { get; set; }
        SecurePipelineListener Listener { get; }
        void SetClientRandom(ReadableBuffer readableBuffer);
        void StartHandshake(ref WritableBuffer writer);
        void HandleAlertMessage(ReadableBuffer readable);
        Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe);
    }
}
