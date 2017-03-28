using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace Leto.Sessions
{
    public interface ISessionProvider
    {
        Span<byte> ProcessSessionTicket(Span<byte> sessionTicket, Guid key, long nounce);
        (long nounce, DateTime ticketExpiry, Guid keyId) GetNextNounce();
        void EncryptSessionKey(ref WritableBuffer writer, int preambleLength, long nouce, Guid key);
    }
}
