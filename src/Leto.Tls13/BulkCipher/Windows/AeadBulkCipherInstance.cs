using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using Leto.Tls13.Interop.Windows;
using Leto.Tls13.RecordLayer;
using Microsoft.Win32.SafeHandles;
using static Interop.BCrypt;

namespace Leto.Tls13.BulkCipher.Windows
{
    public class AeadBulkCipherInstance : IBulkCipherInstance
    {
        private static readonly IntPtr s_zeroBuffer = Marshal.AllocHGlobal(255);
        private int _keyLength;
        private int _iVLength;
        private int _overhead;
        private SafeBCryptAlgorithmHandle _algo;
        private SafeBCryptKeyHandle _key;
        private string _chainingMode;
        private int _paddingSize = 0;
        private EphemeralBufferPoolWindows _bufferPool;
        private OwnedMemory<byte> _keyStore;
        private IntPtr _ivPointer;
        private byte[] _sequence;
        private int _blockLength;
        private int _maxTagLength;
        private ulong _sequenceNumber;

        internal unsafe AeadBulkCipherInstance(SafeBCryptAlgorithmHandle algo, EphemeralBufferPoolWindows bufferPool, BulkCipherType cipherType)
        {
            _bufferPool = bufferPool;
            _algo = algo;
            switch (cipherType)
            {
                case BulkCipherType.AES_128_GCM:
                    _chainingMode = BCRYPT_CHAIN_MODE_GCM;
                    _keyLength = 16;
                    _iVLength = 16;
                    _overhead = 16;
                    break;
                case BulkCipherType.AES_256_GCM:
                    _chainingMode = BCRYPT_CHAIN_MODE_GCM;
                    _keyLength = 32;
                    _iVLength = 16;
                    _overhead = 16;
                    break;
                default:
                    Internal.ExceptionHelper.ThrowException(new InvalidOperationException());
                    return;
            }
            _keyStore = bufferPool.Rent(0);
            void* tmpPointer;
            if (!_keyStore.Memory.TryGetPointer(out tmpPointer))
            {
                throw new InvalidOperationException("Could not get keystore pointer");
            }
            _ivPointer = (IntPtr)tmpPointer;
        }

        public int IVLength => _iVLength;
        public int KeyLength => _keyLength;
        public int Overhead => _paddingSize + _overhead;

        public unsafe void Decrypt(ref ReadableBuffer messageBuffer)
        {
            var tag = stackalloc byte[_overhead];
            messageBuffer.Slice(messageBuffer.Length - _overhead).CopyTo(new Span<byte>(tag, _overhead));
            messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - _overhead);

            throw new NotImplementedException();
        }

        public unsafe void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, RecordType recordType)
        {
            var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            cInfo.dwInfoVersion = 1;
            cInfo.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
            cInfo.cbNonce = _iVLength;
            cInfo.pbNonce = _ivPointer;
            var iv = stackalloc byte[_blockLength];
            var macRecord = stackalloc byte[_maxTagLength];
            var tag = stackalloc byte[_overhead];
            cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.ChainCalls;
            cInfo.cbMacContext = _maxTagLength;
            cInfo.pbMacContext = (IntPtr)macRecord;
            cInfo.pbTag = (IntPtr)tag;
            cInfo.cbTag = _overhead;
            cInfo.pbAuthData = _ivPointer;
            cInfo.cbAuthData = 0;
            var totalDataLength = plainText.Length;
            int outLength;
            GCHandle inHandle, outHandle;
            foreach (var b in plainText)
            {
                totalDataLength = totalDataLength - b.Length;
                if (b.Length == 0 && totalDataLength > 0)
                {
                    continue;
                }
                buffer.Ensure(b.Length);
                var inPtr = b.GetPointer(out inHandle);
                var outPtr = buffer.Memory.GetPointer(out outHandle);
                try
                {
                    outLength = buffer.Memory.Length;
                    int amountWritten;
                    Interop.Windows.ExceptionHelper.CheckReturnCode(BCryptEncrypt(_key, inPtr, b.Length, &cInfo, iv, _blockLength, outPtr, b.Length, out amountWritten, 0));
                    cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.InProgress;
                    buffer.Advance(amountWritten);
                }
                finally
                {
                    if (inHandle.IsAllocated)
                    {
                        inHandle.Free();
                    }
                    if (outHandle.IsAllocated)
                    {
                        outHandle.Free();
                    }
                }
                if (totalDataLength == 0)
                {
                    break;
                }
            }
            buffer.Ensure(Overhead + sizeof(RecordType));
            var writePtr = buffer.Memory.GetPointer(out outHandle);
            outLength = buffer.Memory.Length;
            if (_paddingSize == 0)
            {
                cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
            }
            Interop.Windows.ExceptionHelper.CheckReturnCode(BCryptEncrypt(_key, &recordType, sizeof(RecordType), &cInfo, iv, _iVLength, writePtr, buffer.Memory.Length, out outLength, 0));
            buffer.Advance(outLength);
            if (_paddingSize > 0)
            {
                outLength = _paddingSize;
                writePtr = buffer.Memory.GetPointer(out outHandle);
                cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
                Interop.Windows.ExceptionHelper.CheckReturnCode(BCryptEncrypt(_key, (void*)s_zeroBuffer, _paddingSize, &cInfo, iv, _iVLength, writePtr, buffer.Memory.Length, out outLength, 0));
                buffer.Advance(outLength);
            }
            writePtr = buffer.Memory.GetPointer(out outHandle);
            buffer.Write(new Span<byte>(tag, _overhead));
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
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Failed to increment sequence in Aead Cipher");
        }

        public unsafe void SetIV(Span<byte> iv)
        {
            byte* ivPtr = (byte*)_ivPointer;
            for (int i = 0; i < _iVLength; i++)
            {
                ivPtr[i] = (byte)(iv[i] ^ 0x0);
            }
        }

        public unsafe void SetKey(Span<byte> key)
        {
            var keyBlob = stackalloc byte[sizeof(BCRYPT_KEY_DATA_BLOB) + _keyLength];
            BCRYPT_KEY_DATA_BLOB* pkeyDataBlob = (BCRYPT_KEY_DATA_BLOB*)keyBlob;
            pkeyDataBlob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
            pkeyDataBlob->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
            pkeyDataBlob->cbKeyData = _keyLength;
            var keyBlobSpan = new Span<byte>(keyBlob + sizeof(BCRYPT_KEY_DATA_BLOB), _keyLength);
            key.CopyTo(keyBlobSpan);
            Interop.Windows.ExceptionHelper.CheckReturnCode(
                BCryptImportKey(_algo, IntPtr.Zero, "KeyDataBlob", out _key, IntPtr.Zero, 0, (IntPtr)keyBlob, sizeof(BCRYPT_KEY_DATA_BLOB) + _keyLength, 0));
            BCryptPropertiesHelper.SetBlockChainingMode(_key, _chainingMode);
            _blockLength = BCryptPropertiesHelper.GetBlockLength(_key);
            _maxTagLength = _blockLength;
        }

        public void WithPadding(int paddingSize)
        {
            _paddingSize = paddingSize;
        }

        public void Dispose()
        {
            _bufferPool.Return(_keyStore);
            _keyStore = null;
            _key.Dispose();
            GC.SuppressFinalize(this);
        }

        public void Encrypt(ref WritableBuffer buffer, Span<byte> plainText, RecordType recordType)
        {
            throw new NotImplementedException();
        }

        public void DecryptWithAuthData(ref ReadableBuffer messageBuffer)
        {
            throw new NotImplementedException();
        }

        public unsafe void EncryptWithAuthData(ref WritableBuffer buffer, ReadableBuffer plainText, RecordType recordType, ushort tlsVersion)
        {
            var additionalData = stackalloc byte[13];
            var additionalSpan = new Span<byte>(additionalData, 13);
            additionalSpan.Write64BitNumber(_sequenceNumber);
            additionalSpan = additionalSpan.Slice(8);
            additionalSpan.Write(recordType);
            additionalSpan = additionalSpan.Slice(1);
            additionalSpan.Write(tlsVersion);
            additionalSpan = additionalSpan.Slice(2);
            additionalSpan.Write16BitNumber((ushort)plainText.Length);
            buffer.Ensure(8);
            buffer.Write(new Span<byte>((byte*)_ivPointer + 4, 8));
            var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            cInfo.dwInfoVersion = 1;
            cInfo.cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();
            cInfo.cbNonce = _iVLength;
            cInfo.pbNonce = _ivPointer;
            cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.ChainCalls;
            cInfo.pbAuthData = (IntPtr)additionalData;
            cInfo.cbAuthData = 13;

            var iv = stackalloc byte[16];
            var macRecord = stackalloc byte[16];
            var tag = stackalloc byte[16];
            cInfo.cbMacContext = 16;
            cInfo.pbMacContext = (IntPtr)macRecord;
            cInfo.pbTag = (IntPtr)tag;
            cInfo.cbTag = 16;

            var totalDataLength = plainText.Length;
            foreach (var b in plainText)
            {
                totalDataLength = totalDataLength - b.Length;
                if (b.Length == 0 && totalDataLength > 0)
                {
                    continue;
                }
                if (totalDataLength == 0)
                {
                    cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
                }
                buffer.Ensure(b.Length);
                void* outPointer;
                if (!buffer.Memory.TryGetPointer(out outPointer))
                {
                    throw new NotImplementedException("Need to implement a pinned array if we can get a pointer");
                }
                void* inPointer;
                if (!b.TryGetPointer(out inPointer))
                {
                    throw new NotImplementedException("Need to implement a pinned array if we can't get a pointer");
                }
                int amountWritten;
                Interop.Windows.ExceptionHelper.CheckReturnCode(
                    BCryptEncrypt(_key, inPointer, b.Length, &cInfo, iv, 16, outPointer, buffer.Memory.Length, out amountWritten, 0));
                buffer.Advance(amountWritten);
                cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.InProgress;
                if (totalDataLength == 0)
                {
                    break;
                }
            }
            buffer.Ensure(16);
            buffer.Write(new Span<byte>(tag, 16));

            IncrementSequence();
            _sequenceNumber++;
        }

        public unsafe void EncryptWithAuthData(ref WritableBuffer buffer, Span<byte> plainText, RecordType recordType, ushort tlsVersion)
        {
            var additionalData = stackalloc byte[13];
            var additionalSpan = new Span<byte>(additionalData, 13);
            additionalSpan.Write64BitNumber(_sequenceNumber);
            additionalSpan = additionalSpan.Slice(8);
            additionalSpan.Write(recordType);
            additionalSpan = additionalSpan.Slice(1);
            additionalSpan.Write(tlsVersion);
            additionalSpan = additionalSpan.Slice(2);
            additionalSpan.Write16BitNumber((ushort)plainText.Length);
            buffer.Ensure(8);
            buffer.Write(new Span<byte>((byte*)_ivPointer + 4, 8));
            var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            cInfo.dwInfoVersion = 1;
            cInfo.cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();
            cInfo.cbNonce = _iVLength;
            cInfo.pbNonce = _ivPointer;
            cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
            cInfo.pbAuthData = (IntPtr)additionalData;
            cInfo.cbAuthData = 13;

            var iv = stackalloc byte[16];
            var macRecord = stackalloc byte[16];
            var tag = stackalloc byte[16];
            cInfo.cbMacContext = 16;
            cInfo.pbMacContext = (IntPtr)macRecord;
            cInfo.pbTag = (IntPtr)tag;
            cInfo.cbTag = 16;

            buffer.Ensure(plainText.Length);
            void* outPointer;
            if (!buffer.Memory.TryGetPointer(out outPointer))
            {
                throw new NotImplementedException("Need to implement a pinned array if we can get a pointer");
            }
            plainText.CopyTo(buffer.Memory.Span);
            int amountWritten;
            Interop.Windows.ExceptionHelper.CheckReturnCode(
                BCryptEncrypt(_key, outPointer, plainText.Length, &cInfo, iv, 16, outPointer, buffer.Memory.Length, out amountWritten, 0));
            buffer.Advance(amountWritten);
            cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.InProgress;
            buffer.Ensure(16);
            buffer.Write(new Span<byte>(tag, 16));

            IncrementSequence();
            _sequenceNumber++;
        }

        ~AeadBulkCipherInstance()
        {
            Dispose();
        }
    }
}
