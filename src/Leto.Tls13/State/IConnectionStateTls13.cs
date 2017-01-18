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
    public interface IConnectionStateTls13 : IConnectionState
    {
        ICertificate Certificate { get; set; }
        CertificateList CertificateList { get; }
        KeySchedule KeySchedule { get; set; }
        SecurePipelineListener Listener { get; }
        int PskIdentity { get; set; }
        PskKeyExchangeMode PskKeyExchangeMode { get; set; }
        ResumptionProvider ResumptionProvider { get; }
        string ServerName { get; set; }
        SignatureScheme SignatureScheme { get; set; }
        bool EarlyDataSupported { get; set; }
        void HandshakeContext(ReadableBuffer readable);
        void SetClientRandom(ReadableBuffer readableBuffer);
    }
}