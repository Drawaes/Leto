using Leto.BulkCiphers;
using Leto.Certificates;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using Leto.KeyExchanges;
using System;
using System.IO.Pipelines;
using System.Threading.Tasks;

namespace Leto.ConnectionStates
{
    public interface IConnectionState : IDisposable
    {
        CipherSuite CipherSuite { get; }
        void ChangeCipherSpec();
        WritableBufferAwaitable HandleClientHello(ClientHelloParser clientHelloParser);
        IHash HandshakeHash { get; }
        TlsVersion RecordVersion { get; }
        AeadBulkCipher ReadKey { get; }
        AeadBulkCipher WriteKey { get; }
        bool HandshakeComplete { get; }
    }
}
