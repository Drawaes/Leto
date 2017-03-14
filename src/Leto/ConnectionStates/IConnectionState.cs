using Leto.CipherSuites;
using System.IO.Pipelines;

namespace Leto.ConnectionStates
{
    public interface IConnectionState
    {
        CipherSuite CipherSuite { get; }
        void HandleHandshakeRecord(ref ReadableBuffer record, ref WritableBuffer writer);
        void HandleChangeCipherSpecRecord(ref ReadableBuffer record, ref WritableBuffer writer);
        void HandleApplicationRecord(ref ReadableBuffer record, ref WritableBuffer writer);
        void HandAlertRecord(ref ReadableBuffer record, ref WritableBuffer writer);
    }
}
