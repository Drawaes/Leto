using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13;
using Leto.Tls13.Internal;
using Leto.Tls13.RecordLayer;
using static Interop.BCrypt;
using static Interop.LibCrypto;

namespace Leto.Tls13.BulkCipher.OpenSsl11
{
    public class AeadBulkCipherInstance : IBulkCipherInstance
    {
        private static readonly IntPtr s_zeroBuffer = Marshal.AllocHGlobal(255);
        private IntPtr _cipherType;
        private int _iVLength;
        private int _keyLength;
        private EVP_CIPHER_CTX _ctx;
        private EphemeralBufferPoolWindows _bufferPool;
        private OwnedMemory<byte> _keyStore;
        private IntPtr _ivPointer;
        private IntPtr _keyPointer;
        private int _paddingSize;
        private byte[] _sequence;
        private int _overhead;
        private ulong _sequenceNumber;

        static AeadBulkCipherInstance()
        {
            var array = new byte[255];
            Marshal.Copy(array, 0, s_zeroBuffer, array.Length);
        }

        internal unsafe AeadBulkCipherInstance(IntPtr cipherType, EphemeralBufferPoolWindows bufferPool, int ivLength, int keySize, int overhead)
        {
            _overhead = overhead;
            _bufferPool = bufferPool;
            _cipherType = cipherType;
            _iVLength = EVP_CIPHER_iv_length(cipherType);
            _sequence = new byte[_iVLength];
            _keyLength = keySize;
            _keyStore = bufferPool.Rent(0);
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

        public unsafe void SetKey(Span<byte> key)
        {
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
            var tag = stackalloc byte[_overhead];
            messageBuffer.Slice(messageBuffer.Length - _overhead).CopyTo(new Span<byte>(tag, _overhead));
            messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - _overhead);

            ThrowOnError(EVP_CipherInit_ex(_ctx, _cipherType, IntPtr.Zero, (void*)_keyPointer, (void*)_ivPointer, (int)KeyMode.Decryption));
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
            IncrementSequence();
        }
        
        public unsafe void Encrypt(ref WritableBuffer buffer, RecordType recordType)
        {
            int outLength;
            GCHandle inHandle;
            ThrowOnError(EVP_CipherInit_ex(_ctx, _cipherType, IntPtr.Zero, (void*)_keyPointer, (void*)_ivPointer, (int)KeyMode.Encryption));
            foreach (var b in buffer.AsReadableBuffer())
            {
                if (b.Length == 0)
                {
                    continue;
                }
                var inPtr = b.GetPointer(out inHandle);
                try
                {
                    outLength = buffer.Memory.Length;
                    ThrowOnError(EVP_CipherUpdate(_ctx, inPtr, ref outLength, inPtr, b.Length));
                    buffer.Advance(outLength);
                }
                finally
                {
                    if (inHandle.IsAllocated)
                    {
                        inHandle.Free();
                    }
                }
            }
            buffer.Ensure(Overhead + sizeof(RecordType));
            var writePtr = buffer.Memory.GetPointer(out inHandle);
            outLength = buffer.Memory.Length;
            ThrowOnError(EVP_CipherUpdate(_ctx, writePtr, ref outLength, &recordType, sizeof(RecordType)));
            buffer.Advance(outLength);
            if (_paddingSize > 0)
            {
                outLength = _paddingSize;
                writePtr = buffer.Memory.GetPointer(out inHandle);
                ThrowOnError(EVP_CipherUpdate(_ctx, writePtr, ref outLength, (byte*)s_zeroBuffer, _paddingSize));
                buffer.Advance(outLength);
            }
            writePtr = buffer.Memory.GetPointer(out inHandle);
            outLength = 0;
            ThrowOnError(EVP_CipherFinal_ex(_ctx, null, ref outLength));
            ThrowOnError(EVP_CIPHER_CTX_ctrl(_ctx, EVP_CIPHER_CTRL.EVP_CTRL_GCM_GET_TAG, _overhead, writePtr));
            buffer.Advance(_overhead);
            IncrementSequence();
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
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Failed to increment sequence on Aead Cipher");
        }

        public void WithPadding(int paddingSize)
        {
            _paddingSize = paddingSize;
        }

        public void Dispose()
        {
            _ctx.Free();
            if (_keyStore != null)
            {
                
                _bufferPool.Return(_keyStore);
                _keyStore = null;
            }
            GC.SuppressFinalize(this);
        }

        public unsafe void DecryptWithAuthData(ref ReadableBuffer buffer)
        {
            var additionalData = stackalloc byte[13];
            var spanAdditional = new Span<byte>(additionalData, 13);
            spanAdditional.Write64BitNumber(_sequenceNumber);
            spanAdditional = spanAdditional.Slice(8);
            buffer.Slice(0, 3).CopyTo(spanAdditional);
            spanAdditional = spanAdditional.Slice(3);
            var newLength = buffer.Slice(3, 2).ReadBigEndian<ushort>() - _overhead - 8;
            spanAdditional.Write16BitNumber((ushort)newLength);
            buffer = buffer.Slice(5);
            var nSpan = new Span<byte>((byte*)_ivPointer, _iVLength);
            buffer.Slice(0, 8).CopyTo(nSpan.Slice(4));
            buffer = buffer.Slice(8);

            var cipherText = buffer.Slice(0, newLength);
            var authTag = buffer.Slice(newLength, _overhead);
            buffer = buffer.Slice(0,newLength);
            void* authPtr;
            GCHandle authHandle = default(GCHandle);
            try
            {
                if (authTag.IsSingleSpan)
                {
                    if (!authTag.First.TryGetPointer(out authPtr))
                    {
                        throw new NotImplementedException();
                    }
                }
                else
                {
                    var authTagArray = authTag.ToArray();
                    authHandle = GCHandle.Alloc(authTagArray, GCHandleType.Pinned);
                    authPtr = (void*)authHandle.AddrOfPinnedObject();
                }
                ThrowOnError(EVP_CipherInit_ex(_ctx, _cipherType, IntPtr.Zero, (byte*)_keyPointer, (void*)_ivPointer, (int)KeyMode.Decryption));
                ThrowOnError(EVP_CIPHER_CTX_ctrl(_ctx, EVP_CIPHER_CTRL.EVP_CTRL_GCM_SET_TAG, _overhead, authPtr));
                int resultSize = 0;
                ThrowOnError(EVP_CipherUpdate(_ctx, null, ref resultSize, additionalData, 13));
                int amountToWrite = cipherText.Length;
                foreach (var b in cipherText)
                {
                    amountToWrite -= b.Length;
                    if (b.Length == 0 && b.Length == 0)
                    {
                        continue;
                    }
                    GCHandle memHandle = default(GCHandle);
                    try
                    {
                        void* ptr = b.GetPointer(out memHandle);
                        int size = b.Length;
                        ThrowOnError(EVP_CipherUpdate(_ctx, ptr, ref size, ptr, size));
                    }
                    catch
                    {
                        if (!memHandle.IsAllocated)
                        {
                            memHandle.Free();
                        }
                    }
                    var outLength = 0;
                    ThrowOnError(EVP_CipherFinal_ex(_ctx, null, ref outLength));
                    IncrementSequence();
                    _sequenceNumber++;
                }
            }
            finally
            {
                if (authHandle.IsAllocated)
                {
                    authHandle.Free();
                }
            }
        }
        
        public unsafe void EncryptWithAuthData(ref WritableBuffer buffer, RecordType recordType, ushort tlsVersion, int plaintextLength)
        {
            var additionalData = stackalloc byte[13];
            var additionalSpan = new Span<byte>(additionalData, 13);
            additionalSpan.Write64BitNumber(_sequenceNumber);
            additionalSpan = additionalSpan.Slice(8);
            additionalSpan.Write(recordType);
            additionalSpan = additionalSpan.Slice(1);
            additionalSpan.Write(tlsVersion);
            additionalSpan = additionalSpan.Slice(2);
            additionalSpan.Write16BitNumber((ushort)plaintextLength);
            
            var plainText = buffer.AsReadableBuffer();
            plainText = plainText.Slice(plainText.Length-plaintextLength);

            ThrowOnError(EVP_CipherInit_ex(_ctx, _cipherType, IntPtr.Zero, (byte*)_keyPointer, (void*)_ivPointer, (int)KeyMode.Encryption));
            int outSize = 0;
            ThrowOnError(EVP_CipherUpdate(_ctx, null, ref outSize, additionalData, 13));
            void* inPointer;
            foreach (var b in plainText)
            {
                if (b.Length == 0)
                {
                    continue;
                }   
                b.TryGetPointer(out inPointer);
                outSize = b.Length;
                ThrowOnError(EVP_CipherUpdate(_ctx, inPointer, ref outSize, inPointer, outSize));
            }
            buffer.Ensure(_overhead);
            buffer.Memory.TryGetPointer(out inPointer);
            ThrowOnError(EVP_CipherFinal_ex(_ctx, null, ref outSize));
            ThrowOnError(EVP_CIPHER_CTX_ctrl(_ctx, EVP_CIPHER_CTRL.EVP_CTRL_GCM_GET_TAG, _overhead, inPointer));
            buffer.Advance(_overhead);
            _sequenceNumber++;
            IncrementSequence();
        }

        public unsafe void WriteNonce(ref WritableBuffer buffer)
        {
             buffer.Write(new Span<byte>((byte*)_ivPointer + 4, 8));
        }

        ~AeadBulkCipherInstance()
        {
            Dispose();
        }
    }
}
