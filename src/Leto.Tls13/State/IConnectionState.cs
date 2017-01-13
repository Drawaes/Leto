using System;
using System.IO.Pipelines;
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
    public interface IConnectionState:IDisposable
    {
        ICertificate Certificate { get; set;}
        CertificateList CertificateList { get; }
        CipherSuite CipherSuite { get; set;}
        CryptoProvider CryptoProvider { get;}
        IBulkCipherInstance EarlyDataKey { get; set;}
        IHashInstance HandshakeHash { get; set; }
        KeySchedule KeySchedule { get; set; }
        IKeyshareInstance KeyShare { get; set; }
        SecurePipelineListener Listener { get; }
        int PskIdentity { get; set;}
        PskKeyExchangeMode PskKeyExchangeMode { get; set; }
        IBulkCipherInstance ReadKey { get; set; }
        ResumptionProvider ResumptionProvider { get; }
        string ServerName { get; set; }
        SignatureScheme SignatureScheme { get; set;}
        StateType State { get; }
        ushort Version { get; set; }
        IBulkCipherInstance WriteKey { get; set; }
        Signal DataForCurrentScheduleSent { get;}
        Signal WaitForHandshakeToChangeSchedule { get; }
        void StartHandshakeHash(ReadableBuffer readable);
        void HandshakeContext(ReadableBuffer readable);
        Task HandleMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe);
        void WriteHandshake(ref WritableBuffer writer, HandshakeType handshakeType, Func<WritableBuffer, IConnectionState, WritableBuffer> contentWriter);
    }
}