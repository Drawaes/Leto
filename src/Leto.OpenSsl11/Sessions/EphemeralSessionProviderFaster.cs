using System;
using System.Binary;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.BulkCiphers;
using Leto.ConnectionStates.SecretSchedules;
using Leto.Hashes;
using Leto.Internal;
using Leto.Sessions;

namespace Leto.OpenSsl11.Sessions
{
    public class EphemeralSessionProviderFaster : ISessionProvider
    {
        private static readonly TimeSpan _maxTicketAge = TimeSpan.FromDays(1);
        private static readonly byte[] _ticketLabel = Encoding.ASCII.GetBytes("Ephemeral Ticket Generation");
        private ICryptoProvider _cryptoProvider;
        private BlockingCollection<ISymmetricalCipher> _keys = new BlockingCollection<ISymmetricalCipher>();
        private BulkCipherType _cipherType;
        private Guid _keyGuid;
        private long _nounceCounter;


        public EphemeralSessionProviderFaster(int numberOfKeys, ICryptoProvider provider, BulkCipherType cipherType, SecretSchedulePool secretPool)
        {
            _cryptoProvider = provider;
            _cipherType = cipherType;
            _keyGuid = Guid.NewGuid();
            GenerateKeys(secretPool, numberOfKeys);
        }

        /// <summary>
        /// Here we generate the key from random data, then we will use the TLS 1.3 Expand function to ensure that
        /// if there is a weakness in our randoms it is harder to reverse
        /// </summary>
        private void GenerateKeys(SecretSchedulePool pool, int numberOfKeys)
        {
            var buffer = pool.GetKeyBuffer();
            //We use the crypto random function to fill the key buffer initially
            _cryptoProvider.FillWithRandom(buffer.AsSpan());
            //We use the Hkdf expand method to make it harder to exploit any weakness in the random number generator
            _cryptoProvider.HashProvider.HkdfExpandLabel(HashType.SHA512, buffer.AsSpan(), _ticketLabel, new ReadOnlySpan<byte>(), buffer.AsSpan());
            _keys.Add(_cryptoProvider.BulkCipherProvider.GetCipherKey(_cipherType, buffer));
            for (var i = 0; i < (numberOfKeys -1); i++)
            {
                var newBuffer = pool.GetKeyBuffer();
                buffer.Buffer.CopyTo(newBuffer.Buffer);
                _keys.Add(_cryptoProvider.BulkCipherProvider.GetCipherKey(_cipherType, newBuffer));
            }
        }

        public void Dispose()
        {

        }

        public unsafe void EncryptSessionKey(ref WritableBuffer writer, Span<byte> ticketContent)
        {
            var tagLength = 16;
            var key = _keys.Take();
            try
            {
                var contentLength = ticketContent.Length + tagLength + sizeof(long) + sizeof(Guid);
                var nonce = System.Threading.Interlocked.Increment(ref _nounceCounter);
                writer.WriteBigEndian((ushort)contentLength);
                writer.Ensure(contentLength);

                key.IV.Slice(4).Span.Write(nonce);
                key.Init(KeyMode.Encryption);

                writer.WriteBigEndian(_keyGuid);
                writer.WriteBigEndian(_nounceCounter);

                var amountWritten = key.Finish(ticketContent, writer.Buffer.Span);
                writer.Advance(amountWritten);
                key.GetTag(writer.Buffer.Span.Slice(0, tagLength));
                writer.Advance(tagLength);
            }
            finally
            {
                _keys.Add(key);
            }
        }

        public DateTime GetCurrentExpiry() => DateTime.UtcNow.Add(_maxTicketAge);

        public BigEndianAdvancingSpan ProcessSessionTicket(BigEndianAdvancingSpan sessionTicket)
        {
            var keyId = sessionTicket.Read<Guid>();
            if (keyId != _keyGuid)
            {
                return new BigEndianAdvancingSpan();
            }
            var key = _keys.Take();
            try
            {
                var nounce = sessionTicket.Read<long>();
                key.IV.Span.Slice(4).Write(nounce);
                key.Init(KeyMode.Decryption);
                var span = sessionTicket.ToSpan();
                key.SetTag(span.Slice(span.Length - 16));
                key.Finish(span.Slice(0, span.Length - 16));
                return new BigEndianAdvancingSpan(span.Slice(0, span.Length - 16));
            }
            finally
            {
                _keys.Add(key);
            }

        }
    }
}
