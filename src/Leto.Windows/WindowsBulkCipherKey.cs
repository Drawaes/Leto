using Leto.BulkCiphers;
using System;
using System.Collections.Generic;
using System.Text;
using System.Buffers;
using Microsoft.Win32.SafeHandles;
using static Leto.Windows.Interop.BCrypt;
using System.Binary;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace Leto.Windows
{
    public class WindowsBulkCipherKey : IBulkCipherKey
    {
        private Buffer<byte> _iv;
        private int _tagSize;
        private SafeBCryptKeyHandle _keyHandle;
        private BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO _context;
        private BufferHandle _ivHandle;
        private KeyMode _keyMode;
        private OwnedBuffer<byte> _scratchSpace;
        private BufferHandle _scratchPin;

        internal WindowsBulkCipherKey(SafeBCryptAlgorithmHandle type, Buffer<byte> keyStore, int keySize, int ivSize, int tagSize, string chainingMode, OwnedBuffer<byte> scratchSpace)
        {
            _scratchSpace = scratchSpace;
            _scratchPin = _scratchSpace.Buffer.Pin();
            _tagSize = tagSize;
            _iv = keyStore.Slice(keySize, ivSize);
            _ivHandle = _iv.Pin();
            _keyHandle = BCryptImportKey(type, keyStore.Span.Slice(0, keySize));
        }

        public Buffer<byte> IV => _iv;
        public int TagSize => _tagSize;
        private unsafe byte* MacContextPointer => (byte*)_scratchPin.PinnedPointer;
        private unsafe byte* TagPointer => MacContextPointer + _tagSize;
        private unsafe byte* TempIVPointer => TagPointer + _tagSize;
        private unsafe byte* AuthDataPointer => TempIVPointer + _tagSize;


        public unsafe void AddAdditionalInfo(ref AdditionalInfo addInfo)
        {
            _context.pbAuthData = AuthDataPointer;
            _context.cbAuthData = Unsafe.SizeOf<AdditionalInfo>();
            Unsafe.Write(AuthDataPointer, addInfo);
        }

        public unsafe void Init(KeyMode mode)
        {
            _keyMode = mode;
            _context = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
            {
                dwFlags = AuthenticatedCipherModeInfoFlags.ChainCalls,
                cbMacContext = _tagSize,
                pbMacContext = MacContextPointer,
                cbNonce = _iv.Length,
                pbNonce = _ivHandle.PinnedPointer,
                cbAuthData = 0,
                pbAuthData = null,
                cbTag = _tagSize,
                cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO),
                pbTag = TagPointer,
                dwInfoVersion = 1,
            };
        }

        public unsafe void ReadTag(Span<byte> span)
        {
            if (_keyMode == KeyMode.Encryption)
            {
                BCryptEncryptGetTag(_keyHandle, _context, TempIVPointer);
                var tagSpan = new Span<byte>(TagPointer, _tagSize);
                tagSpan.CopyTo(span);
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        public unsafe int Update(Span<byte> input, Span<byte> output)
        {
            var totalWritten = _context.cbData;
            if (_keyMode == KeyMode.Encryption)
            {
                _context = BCryptEncrypt(_keyHandle, input, output, _context, TempIVPointer);
            }
            else
            {
                _context = BCryptDecrypt(_keyHandle, input, output, _context, TempIVPointer);
            }
            totalWritten = _context.cbData - totalWritten;
            return (int)totalWritten;
        }

        public unsafe int Update(Span<byte> inputAndOutput)
        {
            var totalWritten = _context.cbData;
            if (_keyMode == KeyMode.Encryption)
            {
                _context = BCryptEncrypt(_keyHandle, inputAndOutput, _context, TempIVPointer);
            }
            else
            {
                _context = BCryptDecrypt(_keyHandle, inputAndOutput, _context, TempIVPointer);
            }
            totalWritten = _context.cbData - totalWritten;
            return (int)totalWritten;
        }

        public unsafe void WriteTag(ReadOnlySpan<byte> tagSpan) => BCryptDecryptSetTag(_keyHandle, tagSpan, _context, TempIVPointer);

        public void Dispose()
        {
            _scratchPin.Free();
            _scratchSpace?.Dispose();
            _scratchSpace = null;
            _ivHandle.Free();

            _keyHandle?.Dispose();
            _keyHandle = null;
            GC.SuppressFinalize(this);
        }

        ~WindowsBulkCipherKey()
        {
            Dispose();
        }
    }
}
