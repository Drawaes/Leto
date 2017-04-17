using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using static Leto.Windows.Interop.BCrypt;
using static Leto.BufferExtensions;
using System.Binary;
using Leto.Internal;

namespace Leto.Windows.Sessions
{
    public class EphemeralKey : IDisposable
    {
        private OwnedBuffer<byte> _keyAndIvStore;
        private SafeBCryptKeyHandle _keyHandle;
        private const int _keySize = 32;
        private const int _ivRandomSize = 4;
        private long _currentNonce = 0;
        private Guid _currentKeyId = Guid.NewGuid();

        internal EphemeralKey(SafeBCryptAlgorithmHandle algoHandle, OwnedBuffer<byte> keyAndIvStore)
        {
            _keyAndIvStore = keyAndIvStore;
            BCryptGenRandom(keyAndIvStore.Span.Slice(0, _keySize + _ivRandomSize));
            _keyHandle = BCryptImportKey(algoHandle, _keyAndIvStore.Span.Slice(0, _keySize));
            SetBlockChainingMode(_keyHandle, BCRYPT_CHAIN_MODE_GCM);
            var mode = GetBlockChainingMode(_keyHandle);
        }

        public Guid KeyId => _currentKeyId;
        
        public long GetNextNonce() => Interlocked.Increment(ref _currentNonce);
        
        public void Dispose()
        {
            _keyHandle?.Dispose();
            _keyHandle = null;
            _keyAndIvStore?.Dispose();
            _keyAndIvStore = null;
            GC.SuppressFinalize(this);
        }

        ~EphemeralKey()
        {
            Dispose();
        }

        public int Encrypt(long nonce, Span<byte> ticketContent, Span<byte> output)
        {
            var iv = _keyAndIvStore.Span.Slice(_keySize);
            iv.Slice(4).WriteBigEndian(nonce);
            var bytesWritten = BCryptEncrypt(_keyHandle, iv, output.Slice(ticketContent.Length, 16), ticketContent, output.Slice(0,ticketContent.Length));
            return bytesWritten + 16; 
        }

        internal Span<byte> Decrypt(BigEndianAdvancingSpan sessionTicket)
        {
            var nonce = sessionTicket.Read<long>();
            var data = sessionTicket.TakeSlice(sessionTicket.Length - 16).ToSpan();
            var tag = sessionTicket.ToSpan();
            var iv = _keyAndIvStore.Span.Slice(_keySize);
            iv.Slice(4).WriteBigEndian(nonce);
            BCryptDecrypt(_keyHandle, iv, tag, data);
            return data;
        }
    }
}
