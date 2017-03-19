using Leto.Certificates;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System;
using System.IO.Pipelines;
using System.Threading.Tasks;

namespace Leto.ConnectionStates
{
    public interface IConnectionState : IDisposable
    {
        CipherSuite CipherSuite { get; }
        Task HandleHandshakeRecord(ReadableBuffer record);
        Task HandleChangeCipherSpecRecord(ReadableBuffer record);
        Task HandleClientHello(ClientHelloParser clientHelloParser);
        IHash HandshakeHash { get; }
        ushort RecordVersion { get; }
    }
}
