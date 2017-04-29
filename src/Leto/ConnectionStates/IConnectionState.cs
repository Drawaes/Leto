using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System;
using System.IO.Pipelines;

namespace Leto.ConnectionStates
{
    public interface IConnectionState : IDisposable, IKeyPair
    {
        CipherSuite CipherSuite { get; }
        void ChangeCipherSpec();
        bool ProcessHandshake();
        IHash HandshakeHash { get; }
        TlsVersion RecordVersion { get; }
        bool HandshakeComplete { get; }
    }
}
