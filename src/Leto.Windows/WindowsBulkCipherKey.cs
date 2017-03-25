using Leto.BulkCiphers;
using System;
using System.Collections.Generic;
using System.Text;
using System.Buffers;
using Microsoft.Win32.SafeHandles;
using static Leto.Windows.Interop.BCrypt;

namespace Leto.Windows
{
    public class WindowsBulkCipherKey : IBulkCipherKey
    {
        private Buffer<byte> _key;
        private Buffer<byte> _iv;
        private int _tagSize;
        private SafeBCryptAlgorithmHandle _type;
        private SafeBCryptKeyHandle _keyHandle;
        private int _blockLength;
        private BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO _context;
        private BufferHandle _ivHandle;
        private BufferHandle _contextHandle;
        private KeyMode _keyMode;

        internal WindowsBulkCipherKey(SafeBCryptAlgorithmHandle type, Buffer<byte> keyStore, int keySize, int ivSize, int tagSize, string chainingMode)
        {
            _tagSize = tagSize;
            _key = keyStore.Slice(0, keySize);
            _iv = keyStore.Slice(keySize, ivSize);
            _type = type;
            _keyHandle = BCryptImportKey(_type, _key.Span);
            SetBlockChainingMode(_keyHandle, chainingMode);
            _blockLength = GetBlockLength(_keyHandle);
            _contextHandle = _key.Pin();
            _ivHandle = _iv.Pin();
        }

        public Buffer<byte> Key => _key;
        public Buffer<byte> IV => _iv;
        public int TagSize => _tagSize;
        private unsafe void* AuthPointer => ((byte*)_contextHandle.PinnedPointer) + _blockLength;
        private unsafe Span<byte> AuthSpan => new Span<byte>(AuthPointer, sizeof(AdditionalInfo));

        public unsafe void AddAdditionalInfo(AdditionalInfo addInfo)
        {
            AuthSpan.Write(addInfo);
            _context.pbAuthData = AuthPointer;
            _context.cbAuthData = AuthSpan.Length;
        }

        public unsafe void Init(KeyMode mode)
        {
            _keyMode = mode;
            _context = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
            {
                dwFlags = AuthenticatedCipherModeInfoFlags.ChainCalls,
                cbMacContext = _blockLength,
                pbMacContext = _contextHandle.PinnedPointer,
                cbNonce = _iv.Length,
                pbNonce = _ivHandle.PinnedPointer,
                cbAuthData = 0,
                pbAuthData = null,
                cbTag = _tagSize
            };
        }

        public void ReadTag(Span<byte> span)
        {
            if (_keyMode == KeyMode.Encryption)
            {
                BCryptEncryptGetTag(_keyHandle, span, _context);
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        public int Update(Span<byte> input, Span<byte> output)
        {
            var totalWritten = _context.cbData;
            if (_keyMode == KeyMode.Encryption)
            {
                _context = BCryptEncrypt(_keyHandle, input, output, _context);
            }
            else
            {
                _context = BCryptDecrypt(_keyHandle, input, output, _context);
            }
            totalWritten = _context.cbData - totalWritten;
            return (int)totalWritten;
        }

        public int Update(Span<byte> inputAndOutput)
        {
            var totalWritten = _context.cbData;
            if (_keyMode == KeyMode.Encryption)
            {
                _context = BCryptEncrypt(_keyHandle, inputAndOutput, _context);
            }
            else
            {
                _context = BCryptDecrypt(_keyHandle, inputAndOutput, _context);
            }
            totalWritten = _context.cbData - totalWritten;
            return (int)totalWritten;
        }

        public void WriteTag(ReadOnlySpan<byte> tagSpan)
        {
            BCryptDecryptSetTag(_keyHandle, tagSpan, _context);
        }

        public void Dispose()
        {
            _contextHandle.Free();
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
