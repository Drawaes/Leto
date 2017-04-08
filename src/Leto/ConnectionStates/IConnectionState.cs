using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System;
using System.IO.Pipelines;

namespace Leto.ConnectionStates
{
    public interface IConnectionState : IDisposable
    {
        CipherSuite CipherSuite { get; }
        void ChangeCipherSpec();
        bool HandleClientHello(ref ClientHelloParser clientHelloParser);
        bool ProcessHandshake();
        IHash HandshakeHash { get; }
        TlsVersion RecordVersion { get; }
        AeadBulkCipher ReadKey { get; }
        AeadBulkCipher WriteKey { get; }
        bool HandshakeComplete { get; }
    }
}
