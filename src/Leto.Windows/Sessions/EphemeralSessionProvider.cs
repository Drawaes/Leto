using Leto.Sessions;
using System;
using System.Collections.Generic;
using System.Text;
using System.IO.Pipelines;
using System.Buffers;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using static Leto.Windows.Interop.BCrypt;
using System.Runtime.InteropServices;
using Leto.Internal;

namespace Leto.Windows.Sessions
{
    public class EphemeralSessionProvider : ISessionProvider, IDisposable
    {
        private TimeSpan _maxTicketAge = TimeSpan.FromDays(1);
        private EphemeralKey _currentKey;
        private Buffer<byte> _ivRandom;
        private OwnedBuffer<byte> _keyStorage;
        private SafeBCryptKeyHandle _keyHandle;
        private EphemeralBufferPoolWindows _bufferPool = new EphemeralBufferPoolWindows(44, 100);


        public EphemeralSessionProvider()
        {
            _keyStorage = _bufferPool.Rent(0);
            BCryptGenRandom(_keyStorage.Buffer.Span);
            _ivRandom = _keyStorage.Buffer.Slice(32);
        }

        public unsafe void EncryptSessionKey(ref WritableBuffer writer, Span<byte> ticketContent)
        {
            var key = _currentKey;
            var nonce = key.GetNextNonce(); 
            writer.WriteBigEndian(key.KeyId);
            writer.WriteBigEndian(nonce);
            var tag = new byte[16];
            var iv = new byte[12];
            var ivSpan = (Span<byte>)iv;
            _ivRandom.CopyTo(ivSpan);
            ivSpan.Slice(_ivRandom.Length).WriteBigEndian(nonce);
            writer.Ensure(ticketContent.Length);
            BCryptEncrypt(_keyHandle, iv, tag, ticketContent, writer.Buffer.Span);
            writer.Write(tag);
        }

        public Span<byte> ProcessSessionTicket(Span<byte> sessionTicket)
        {
            throw new NotImplementedException();
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
