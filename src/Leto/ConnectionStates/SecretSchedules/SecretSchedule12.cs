using System;
using System.Buffers;
using Leto.Hashes;
using static Leto.BufferExtensions;
using Leto.BulkCiphers;
using static Leto.TlsConstants;
using System.Runtime.InteropServices;
using System.IO.Pipelines;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedule12 : IDisposable
    {
        private OwnedBuffer<byte> _secretStore;
        private OwnedBuffer<byte> _keyStore;
        private Buffer<byte> _clientRandom;
        private Buffer<byte> _serverRandom;
        private Buffer<byte> _masterSecret;
        private Buffer<byte> _clientKey;
        private Buffer<byte> _serverKey;
        private Buffer<byte> _clientVerify;
        private Buffer<byte> _serverVerify;
        private Server12ConnectionState _state;
        private ICryptoProvider _cryptoProvider;

        public SecretSchedule12(Server12ConnectionState state)
        {
            _state = state;
            (_secretStore, _keyStore) = state.SecureConnection.Listener.SecretSchedulePool.GetSecretBuffer();
            var memory = _secretStore.Buffer;
            _clientRandom = SliceAndConsume(ref memory, RandomLength);
            _serverRandom = SliceAndConsume(ref memory, RandomLength);
            _masterSecret = SliceAndConsume(ref memory, Tls12.MasterSecretLength);
            _clientVerify = SliceAndConsume(ref memory, VerifyDataLength);
            _serverVerify = SliceAndConsume(ref memory, VerifyDataLength);
            _cryptoProvider = state.SecureConnection.Listener.CryptoProvider;
            _clientKey = _keyStore.Buffer;
        }

        internal ReadOnlySpan<byte> ClientRandom => _clientRandom.Span;
        internal ReadOnlySpan<byte> ServerRandom => _serverRandom.Span;

        public void SetClientRandom(Span<byte> random)
        {
            random.CopyTo(_clientRandom.Span);
            GenerateServerRandom();
        }

        private void GenerateServerRandom()
        {
            var span = _serverRandom.Span;
            var randomBytes = RandomLength - Tls12.EndOfRandomDowngradeProtection.Length;
            _cryptoProvider.FillWithRandom(span.Slice(0, randomBytes));
            span = span.Slice(randomBytes);
            //https://tlswg.github.io/tls13-spec/#rfc.section.4.1.3
            //Last 8 bytes of random are a special value to protect against downgrade attacks
            Tls12.EndOfRandomDowngradeProtection.CopyTo(span);
        }

        public void GenerateMasterSecret()
        {
            var seed = new byte[RandomLength * 2];
            _clientRandom.Span.CopyTo(seed);
            _serverRandom.Span.CopyTo(seed.Slice(RandomLength));
            _state.Keyshare.DeriveMasterSecret(_cryptoProvider.HashProvider, _state.CipherSuite.HashType, seed, _masterSecret.Span);
            _state.Keyshare.Dispose();
            _state.Keyshare = null;
        }

        public bool GenerateAndCompareClientVerify(Span<byte> clientVerify)
        {
            var hashResult = new byte[_state.HandshakeHash.HashSize];
            _state.HandshakeHash.InterimHash(hashResult);
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span,
                Tls12.Label_ClientFinished, hashResult, _clientVerify.Span);
            _state.HandshakeHash.HashData(clientVerify);
            return Internal.CompareFunctions.ConstantTimeEquals(_clientVerify.Span, clientVerify.Slice(Marshal.SizeOf<Handshake.HandshakeHeader>()));
        }

        public void GenerateAndWriteServerVerify(ref WritableBuffer writer)
        {
            var hashResult = new byte[_state.HandshakeHash.HashSize];
            _state.HandshakeHash.FinishHash(hashResult);
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span,
                Tls12.Label_ServerFinished, hashResult, _serverVerify.Span);
            Handshake.HandshakeFraming.WriteHandshakeFrame(ref writer, null, WriteServerVerify, Handshake.HandshakeType.finished);
            _secretStore.Dispose();
            _secretStore = null;
        }

        private WritableBuffer WriteServerVerify(WritableBuffer writer)
        {
            writer.Write(_serverVerify.Span);
            return writer;
        }

        public (AeadBulkCipher clientKey, AeadBulkCipher serverKey) GenerateKeys()
        {
            var (keySize, ivSize) = _cryptoProvider.BulkCipherProvider.GetCipherSize(_state.CipherSuite.BulkCipherType);
            var materialLength = (keySize + 4) * 2;
            var material = new byte[materialLength];
            var seedLength = _clientRandom.Length * 2;
            var seed = new byte[seedLength];
            _serverRandom.CopyTo((Span<byte>)seed);
            _clientRandom.CopyTo(seed.Slice(_serverRandom.Length));
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_KeyExpansion, seed, material);
            _serverKey = _clientKey.Slice(keySize + ivSize, keySize + ivSize);
            _clientKey = _clientKey.Slice(0, keySize + ivSize);

            material.Slice(0, keySize).CopyTo(_clientKey.Span);
            material.Slice(keySize * 2, 4).CopyTo(_clientKey.Span.Slice(keySize));
            material.Slice(keySize, keySize).CopyTo(_serverKey.Span);
            material.Slice(keySize * 2 + 4, 4).CopyTo(_serverKey.Span.Slice(keySize));
            var clientKey = _cryptoProvider.BulkCipherProvider.GetCipher(_state.CipherSuite.BulkCipherType, _clientKey);
            var serverKey = _cryptoProvider.BulkCipherProvider.GetCipher(_state.CipherSuite.BulkCipherType, _serverKey);
            return (clientKey, serverKey);
        }

        public void Dispose()
        {
            _secretStore?.Dispose();
            _secretStore = null;
            _keyStore?.Dispose();
            _keyStore = null;
            GC.SuppressFinalize(this);
        }

        ~SecretSchedule12()
        {
            Dispose();
        }
    }
}
