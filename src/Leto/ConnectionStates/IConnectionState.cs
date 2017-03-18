using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System;
using System.IO.Pipelines;

namespace Leto.ConnectionStates
{
    public interface IConnectionState:IDisposable
    {
        CipherSuite CipherSuite { get; }
        void HandleHandshakeRecord(ref ReadableBuffer record, ref WritableBuffer writer);
        void HandleChangeCipherSpecRecord(ref ReadableBuffer record, ref WritableBuffer writer);
        void HandleClientHello(ref ClientHelloParser clientHelloParser, ref WritableBuffer writer);
        IHash HandshakeHash { get; }
    }
}
