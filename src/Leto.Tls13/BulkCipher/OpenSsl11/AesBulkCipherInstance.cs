using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using Leto.Tls13.RecordLayer;
using static Interop.LibCrypto;

namespace Leto.Tls13.BulkCipher.OpenSsl11
{
    public class AesBulkCipherInstance : IBulkCipherInstance
    {
        private static readonly IntPtr s_zeroBuffer = Marshal.AllocHGlobal(255);
        private IntPtr _cipherType;
        private int _iVLength;
        private int _keyLength;
        private EVP_CIPHER_CTX _ctx;
        private KeyMode _mode;
        private SecureBufferPool _bufferPool;
        private OwnedMemory<byte> _keyStore;
        private IntPtr _ivPointer;
        private IntPtr _keyPointer;
        private int _paddingSize;
        private byte[] _sequence;
        private int _overhead;

        static AesBulkCipherInstance()
        {
            var array = new byte[255];
            Marshal.Copy(array,0, s_zeroBuffer, array.Length);
        }

        public unsafe AesBulkCipherInstance(IntPtr cipherType, SecureBufferPool bufferPool, int ivLength, int keySize, int overhead)
        {
            _overhead = overhead;
            _bufferPool = bufferPool;
            _cipherType = cipherType;
            _iVLength = EVP_CIPHER_iv_length(cipherType);
            _sequence = new byte[_iVLength];
            _keyLength = keySize;
            _keyStore = bufferPool.Rent();
            void* tmpPointer;
            if (!_keyStore.Memory.TryGetPointer(out tmpPointer))
            {
                throw new InvalidOperationException("Could not get keystore pointer");
            }
            _keyPointer = (IntPtr)tmpPointer;
            _ivPointer = IntPtr.Add(_keyPointer, _keyLength);
        }

        public int IVLength => _iVLength;
        public int KeyLength => _keyLength;
        public int Overhead => _overhead + _paddingSize;

        public unsafe void SetKey(Span<byte> key, KeyMode mode)
        {
            _mode = mode;
            _ctx = EVP_CIPHER_CTX_new();
            key.CopyTo(new Span<byte>(_keyPointer.ToPointer(), _keyLength));
        }

        public unsafe void SetIV(Span<byte> iv)
        {
            byte* ivPtr = (byte*)_ivPointer;
            for (int i = 0; i < _iVLength; i++)
            {
                ivPtr[i] = (byte)(iv[i] ^ 0x0);
            }
        }

        public unsafe void Decrypt(ref ReadableBuffer messageBuffer)
        {
            var tag = stackalloc byte[16];
            messageBuffer.Slice(messageBuffer.Length - 16).CopyTo(new Span<byte>(tag, 16));
            messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - 16);

            ThrowOnError(EVP_CipherInit_ex(_ctx, _cipherType, IntPtr.Zero, (void*)_keyPointer, (void*)_ivPointer, (int)_mode));
            ThrowOnError(EVP_CIPHER_CTX_ctrl(_ctx, EVP_CIPHER_CTRL.EVP_CTRL_GCM_SET_TAG, _overhead, tag));
            int outLength;
            foreach (var b in messageBuffer)
            {
                if (b.Length > 0)
                {
                    GCHandle handle;
                    var ptr = b.GetPointer(out handle);
                    outLength = b.Length;
                    ThrowOnError(EVP_CipherUpdate(_ctx, ptr, ref outLength, ptr, outLength));
                    if (outLength != b.Length)
                    {
                        throw new InvalidOperationException();
                    }
                }
            }
            outLength = 0;
            ThrowOnError(EVP_CipherFinal_ex(_ctx, null, ref outLength));
        }
        
        public unsafe void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, RecordType recordType)
        {
            int outLength;
            GCHandle inHandle, outHandle;
            ThrowOnError(EVP_CipherInit_ex(_ctx, _cipherType, IntPtr.Zero, (void*)_keyPointer, (void*)_ivPointer, (int)_mode));
            foreach(var b in plainText)
            {
                if(b.Length == 0)
                {
                    continue;
                }
                buffer.Ensure(b.Length);
                var inPtr = b.GetPointer(out inHandle);
                var outPtr = buffer.Memory.GetPointer(out outHandle);
                try
                {
                    outLength = buffer.Memory.Length;
                    ThrowOnError(EVP_CipherUpdate(_ctx, outPtr, ref outLength, inPtr, b.Length));
                    buffer.Advance(outLength);
                }
                finally
                {
                    if(inHandle.IsAllocated)
                    {
                        inHandle.Free();
                    }
                    if(outHandle.IsAllocated)
                    {
                        outHandle.Free();
                    }
                }
            }
            buffer.Ensure(Overhead + sizeof(RecordType));
            var writePtr = buffer.Memory.GetPointer(out outHandle);
            outLength = buffer.Memory.Length;
            ThrowOnError(EVP_CipherUpdate(_ctx, writePtr, ref outLength, &recordType, sizeof(RecordType)));
            buffer.Advance(outLength);
            if (_paddingSize > 0)
            {
                outLength = _paddingSize;
                writePtr = buffer.Memory.GetPointer(out outHandle);
                ThrowOnError(EVP_CipherUpdate(_ctx, writePtr, ref outLength, (byte*) s_zeroBuffer, _paddingSize));
                buffer.Advance(outLength);
            }
            writePtr = buffer.Memory.GetPointer(out outHandle);
            outLength = 0;
            ThrowOnError(EVP_CipherFinal_ex(_ctx, null, ref outLength));
            ThrowOnError(EVP_CIPHER_CTX_ctrl(_ctx, EVP_CIPHER_CTRL.EVP_CTRL_GCM_GET_TAG, _overhead, writePtr));
            buffer.Advance(_overhead);
        }

        public unsafe void IncrementSequence()
        {
            var i = _iVLength - 1;
            var vPtr = (byte*)_ivPointer;
            while (i > 3)
            {
                unchecked
                {
                    var val = vPtr[i] ^ _sequence[i];
                    _sequence[i] = (byte)(_sequence[i] + 1);
                    vPtr[i] = (byte)(_sequence[i] ^ val);
                    if (_sequence[i] > 0)
                    {
                        return;
                    }
                }
                i -= 1;
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
        }

        public void WithPadding(int paddingSize)
        {
            _paddingSize = paddingSize;
        }

        public void Dispose()
        {
            _ctx.Free();
            _bufferPool.Return(_keyStore);
            _keyStore = null;
            GC.SuppressFinalize(this);
        }

        ~AesBulkCipherInstance()
        {
            Dispose();
        }
    }
}
