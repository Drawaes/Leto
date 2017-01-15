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
        IHashInstance HandshakeHash { get; set; }
        KeySchedule KeySchedule { get; set; }
        IKeyshareInstance KeyShare { get; set; }
        SecurePipelineListener Listener { get; }
        int PskIdentity { get; set;}
        PskKeyExchangeMode PskKeyExchangeMode { get; set; }
        IBulkCipherInstance ReadKey { get; }
        ResumptionProvider ResumptionProvider { get; }
        string ServerName { get; set; }
        SignatureScheme SignatureScheme { get; set;}
        StateType State { get; set;}
        ushort Version { get; set; }
        IBulkCipherInstance WriteKey { get; }
        Signal DataForCurrentScheduleSent { get;}
        bool EarlyDataSupported { get; set; }
               
        void StartHandshakeHash(ReadableBuffer readable);
        void HandshakeContext(ReadableBuffer readable);
        void HandleAlertMessage(ReadableBuffer readable);
        Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe);
        void StartHandshake(ref WritableBuffer writer);
    }
}