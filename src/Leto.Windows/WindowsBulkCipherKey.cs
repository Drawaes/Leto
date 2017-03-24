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
        private AdditionalInfo _additionalInfo;

        internal WindowsBulkCipherKey(SafeBCryptAlgorithmHandle type, Buffer<byte> keyStore, int keySize, int ivSize, int tagSize, string chainingMode)
        {
            _tagSize = tagSize;
            _key = keyStore.Slice(0, keySize);
            _iv = keyStore.Slice(keySize, ivSize);
            _type = type;
            _keyHandle = BCryptImportKey(_type, _key.Span);
            SetBlockChainingMode(_keyHandle, chainingMode);
            _blockLength = GetBlockLength(_keyHandle);
        }

        public Buffer<byte> Key => _key;
        public Buffer<byte> IV => _iv;
        public int TagSize => _tagSize;

        public void AddAdditionalInfo(AdditionalInfo addInfo)
        {
            _additionalInfo = addInfo;
        }

        public void Finish()
        {
            throw new NotImplementedException();
        }

        public void Init(KeyMode mode)
        {
            _additionalInfo = default(AdditionalInfo);
        }

        public void ReadTag(Span<byte> span)
        {
            throw new NotImplementedException();
        }

        public int Update(Span<byte> input, Span<byte> output)
        {
            throw new NotImplementedException();
        }

        public int Update(Span<byte> inputAndOutput)
        {
            throw new NotImplementedException();
        }

        public void WriteTag(ReadOnlySpan<byte> tagSpan)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
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
