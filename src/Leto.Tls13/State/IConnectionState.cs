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
using Leto.Tls13.RecordLayer;
using Leto.Tls13.Sessions;
using Microsoft.Extensions.Logging;

namespace Leto.Tls13.State
{
    public interface IConnectionState : IDisposable
    {
        ICertificate Certificate { get; set; }
        IBulkCipherInstance ReadKey { get; }
        IBulkCipherInstance WriteKey { get; }
        ILogger Logger { get; }
        StateType State { get; }
        string ServerName { get; set; }
        SignatureScheme SignatureScheme { get; set; }
        TlsVersion Version { get; }
        ResumptionProvider ResumptionProvider { get; }
        CertificateList CertificateList { get; }
        CryptoProvider CryptoProvider { get; }
        IKeyshareInstance KeyShare { get; set; }
        CipherSuite CipherSuite { get; set; }
        bool SecureRenegotiation { get; set; }
        IHashInstance HandshakeHash { get; set; }
        SecurePipeListener Listener { get; }
        ushort TlsRecordVersion { get; }
        FrameWriter FrameWriter { get; }
        Extensions.ApplicationLayerProtocolType NegotiatedApplicationProcotol { get; set;}
        void SetClientRandom(ReadableBuffer readableBuffer);
        void SetServerRandom(Memory<byte> memory);
        void HandleAlertMessage(ReadableBuffer readable);
        void HandleChangeCipherSpec(ReadableBuffer readable);
        void HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer,ref WritableBuffer outBuffer);
    }
}
