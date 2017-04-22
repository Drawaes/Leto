using System;
using System.Collections.Generic;
using System.Text;
using Leto.BulkCiphers;
using Leto.KeyExchanges;

namespace Leto.Internal
{
    public interface ILetoTrace
    {
        void SessionStart(long sessionId);
        void SessionEnd(long sessionId);
        //void BulkKeyCreated(long sessionId, string keyName, Span<byte> keyAndIv, BulkCipherType cipherType);
        //void SecretCreated(long sessionId, string secretName, Span<byte> secret);
        void ExchangeKey(long sessionId, NamedGroup namedGroup, Span<byte> key, bool isPrivate);
        //void ApplicationMessageSent(long sessionId, Span<byte> message);
        //void ApplicationMessageReceived(long sessionId, Span<byte> message);
        //void HandshakeMessageReceived(long sessionId, Span<byte> message);
        //void HandshakeMessageSent(long sessionId, Span<byte> message);
        //void ChangeCipherSpecMessageSent(long sessionId, Span<byte> message);
        //void ChangeCipherSpecMessageReceived(long sessionId, Span<byte> message);
    }
}
