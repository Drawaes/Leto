using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;

namespace Leto.Sessions
{
    public class SessionProvider : ISessionProvider
    {
        private TimeSpan _maxTicketAge = TimeSpan.FromDays(1);
        private long _currentNounce = 0;
        private Guid _currentKeyId = Guid.NewGuid();

        public (long nounce, DateTime ticketExpiry, Guid keyId) GetNextNounce()
        {
            var nounce = Interlocked.Increment(ref _currentNounce);
            return (nounce, DateTime.UtcNow.Add(_maxTicketAge), _currentKeyId);
        }

        public void EncryptSessionKey(ref WritableBuffer writer, int plainTextLength, long nouce, Guid key)
        {
            
            
        }
        
        public Span<byte> ProcessSessionTicket(Span<byte> sessionTicket, Guid key, long nounce)
        {
            return sessionTicket;
        }
    }
}
