using Leto.Sessions;
using System;
using System.Collections.Generic;
using System.Text;
using System.IO.Pipelines;
using System.Buffers;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using static Leto.Windows.Interop.BCrypt;
using static Leto.BufferExtensions;
using System.Runtime.InteropServices;
using Leto.Internal;

namespace Leto.Windows.Sessions
{
    public class EphemeralSessionProvider : ISessionProvider, IDisposable
    {
        private TimeSpan _maxTicketAge = TimeSpan.FromDays(1);
        private EphemeralKey _currentKey;
        private SafeBCryptAlgorithmHandle _algo = BCryptOpenAlgorithmProvider("AES");

        private EphemeralBufferPoolWindows _bufferPool = new EphemeralBufferPoolWindows(44, 100);
        
        public EphemeralSessionProvider()
        {
            SetBlockChainingMode(_algo, BCRYPT_CHAIN_MODE_GCM);
            var keyStorage = _bufferPool.Rent(0);
            BCryptGenRandom(keyStorage.Buffer.Span.Slice(0,44));
            _currentKey = new EphemeralKey(_algo, keyStorage);
        }

        public unsafe void EncryptSessionKey(ref WritableBuffer writer, Span<byte> ticketContent)
        {
            var tagLength = 16;
            var key = _currentKey;
            var nonce = key.GetNextNonce();
            BufferExtensions.WriteVector<ushort>(ref writer, w =>
            {
                w.WriteBigEndian(key.KeyId);
                w.WriteBigEndian(nonce);
                w.Ensure(ticketContent.Length + tagLength);
                var bytesWritten = _currentKey.Encrypt(nonce, ticketContent, w.Buffer.Span);
                w.Advance(bytesWritten);
                return w;
            });
        }

        public Span<byte> ProcessSessionTicket(Span<byte> sessionTicket)
        {
            var keyId = ReadBigEndian<Guid>(ref sessionTicket);
            var key = _currentKey;
            if (keyId != key.KeyId)
            {
                throw new NotImplementedException();
            }
            return key.Decrypt(sessionTicket);
        }

        public DateTime GetCurrentExpiry()
        {
            return DateTime.UtcNow.Add(_maxTicketAge);
        }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        ~EphemeralSessionProvider()
        {
            Dispose();
        }
    }
}
