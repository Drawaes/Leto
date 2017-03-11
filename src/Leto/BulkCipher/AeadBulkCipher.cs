using Leto.RecordLayer;
using System;
using System.Buffers;
using System.Buffers.Pools;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Leto.Interop.LibCrypto;

namespace Leto.BulkCipher
{
    public sealed class AeadBulkCipher : IDisposable
    {
        private static readonly IntPtr s_zeroBuffer = Marshal.AllocHGlobal(byte.MaxValue);
        private const int AdditionalInfoHeaderSize = 13;
        private byte[] _sequence;
        private ulong _sequenceNumber;
        private OpenSslBulkKey _key;
        private byte _paddingSize;

        static AeadBulkCipher()
        {
            var array = new byte[byte.MaxValue];
            Marshal.Copy(array, 0, s_zeroBuffer, array.Length);
        }

        internal AeadBulkCipher(OpenSslBulkKey key)
        {
            _sequence = new byte[key.IV.Length];
            _key = key;
        }

        public byte PaddingSize { get => _paddingSize; set => _paddingSize = value; }
        public int Overhead => _key.TagSize + _paddingSize;
        public int KeySize => _key.Key.Length;
        public int IVSize => _key.IV.Length;

        public unsafe void SetKey(Span<byte> key)
        {
            key.CopyTo(_key.Key.Span);
        }

        public void SetIV(Span<byte> iv)
        {
            var localIv = _key.IV.Span;
            for (var i = 0; i < iv.Length; i++)
            {
                localIv[i] = (byte)(iv[i] ^ 0x0);
            }
        }

        public void Decrypt(ref ReadableBuffer messageBuffer, bool requiresAdditionalInfo)
        {
            int plainTextSize, plainTextStart;
            AdditionalInfo addInfo = default(AdditionalInfo);
            if (requiresAdditionalInfo)
            {
                addInfo = ReadAdditionalInfo(ref messageBuffer);
                _key.Init(KeyMode.Decryption);
                plainTextSize = addInfo.PlainTextLength;
                plainTextStart = AdditionalInfoHeaderSize;
            }
            else
            {
                _key.Init(KeyMode.Decryption);
                plainTextSize = messageBuffer.Length - _key.TagSize;
                plainTextStart = 0;
            }
            ReadTag(ref messageBuffer);
            _key.AddAdditionalInfo(addInfo);
            messageBuffer = messageBuffer.Slice(plainTextStart, plainTextSize);
            foreach (var b in messageBuffer)
            {
                if (b.Length == 0) continue;
                _key.Update(b.Span);
            }
            _key.Finish();
            IncrementSequence();
        }

        public void EncryptWithAuthData(ref WritableBuffer buffer, RecordType recordType, ushort tlsVersion, int plaintextLength)
        {
            var additionalInfo = new AdditionalInfo()
            {
                SequenceNumber = _sequenceNumber,
                RecordType = recordType,
                TlsVersion = tlsVersion,
                PlainTextLength = (ushort)plaintextLength
            };
            var plainText = buffer.AsReadableBuffer();
            plainText = plainText.Slice(plainText.Length - plaintextLength);
            _key.Init(KeyMode.Encryption);
            _key.AddAdditionalInfo(additionalInfo);

            foreach (var b in plainText)
            {
                if (b.Length == 0) continue;
                _key.Update(b.Span);
            }
            _key.Finish();
            buffer.Ensure(_key.TagSize);
            _key.ReadTag(buffer.Memory.Span.Slice(0, _key.TagSize));
            buffer.Advance(_key.TagSize);
            _sequenceNumber++;
            IncrementSequence();
        }

        private unsafe AdditionalInfo ReadAdditionalInfo(ref ReadableBuffer messageBuffer)
        {
            var additionalInfo = new AdditionalInfo() { SequenceNumber = _sequenceNumber };
            var headerSpan = messageBuffer.Slice(0, AdditionalInfoHeaderSize).ToSpan();
            var additionalSpan = new Span<byte>(Unsafe.AsPointer(ref additionalInfo), Marshal.SizeOf<AdditionalInfo>());

            headerSpan.Slice(0, 5).CopyTo(additionalSpan.Slice(sizeof(ulong)));
            var plainTextLength = additionalInfo.PlainTextLength - _key.TagSize - 8;
            additionalInfo.PlainTextLength = (ushort)plainTextLength;

            var nSpan = _key.IV.Span;
            headerSpan.Slice(5).CopyTo(nSpan.Slice(4));

            return additionalInfo;
        }

        private unsafe void ReadTag(ref ReadableBuffer messageBuffer)
        {
            var tagBuffer = messageBuffer.Slice(messageBuffer.Length - _key.TagSize);
            var tagSpan = tagBuffer.ToSpan();
            _key.WriteTag(tagSpan);
        }

        public void IncrementSequence()
        {
            var vPtr = _key.IV.Span;
            var i = vPtr.Length - 1;
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

        public void Dispose()
        {
            _key?.Dispose();
            _key = null;
            GC.SuppressFinalize(this);
        }

        ~AeadBulkCipher()
        {
            Dispose();
        }
    }
}
