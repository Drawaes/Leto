using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using static Leto.Windows.Interop.BCrypt;

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

        public EphemeralKey(OwnedBuffer<byte> keyAndIvStore)
        {
            _keyAndIvStore = keyAndIvStore;
            BCryptGenRandom(keyAndIvStore.Span.Slice(0, _keySize + _ivRandomSize));
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
    }
}
