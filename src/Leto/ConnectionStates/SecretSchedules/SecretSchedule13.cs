using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Leto.BulkCiphers;
using Leto.Hashes;
using static Leto.TlsConstants.Tls13;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedule13
    {
        private ConnectionState _state;
        private ICryptoProvider _cryptoProvider;
        private OwnedBuffer<byte> _secretStore;
        private OwnedBuffer<byte> _keyStore;
        protected Buffer<byte> _secret;
        private int _hashSize;
        private Buffer<byte> _remainingStore;
        private Buffer<byte> _clientTraffic;
        private Buffer<byte> _serverTraffic;
        private Buffer<byte> _finishedKey;
        private int _keySize;
        private int _ivSize;

        public void Init(ConnectionState state, Span<byte> presharedKey)
        {
            (_secretStore, _keyStore) = state.SecureConnection.Listener.SecretSchedulePool.GetSecretBuffer();
            _remainingStore = _secretStore.Buffer;
            _state = state;
            _cryptoProvider = state.SecureConnection.Listener.CryptoProvider;
            _hashSize = _cryptoProvider.HashProvider.HashSize(_state.CipherSuite.HashType);
            _secret = GetBufferSlice(_hashSize);
            _clientTraffic = GetBufferSlice(_hashSize);
            _serverTraffic = GetBufferSlice(_hashSize);
            _finishedKey = GetBufferSlice(_hashSize);
            _cryptoProvider.HashProvider.HkdfExtract(state.CipherSuite.HashType, new Span<byte>(), presharedKey, _secret.Span);
            (_keySize, _ivSize) = _cryptoProvider.BulkCipherProvider.GetCipherSize(_state.CipherSuite.BulkCipherType);
        }

        public virtual (AeadBulkCipher clientKey, AeadBulkCipher serverKey) GenerateHandshakeKeys()
        {
            _state.KeyExchange.DeriveSecret(_cryptoProvider.HashProvider, _state.CipherSuite.HashType, _secret.Span, _secret.Span);
            _state.KeyExchange.Dispose();
            _state.KeyExchange = null;

            var hash = new byte[_hashSize];
            _state.HandshakeHash.InterimHash(hash);
            ExpandLabel(_secret, Label_ClientHandshakeTrafficSecret, hash, _clientTraffic);
            ExpandLabel(_secret, Label_ServerHandshakeTrafficSecret, hash, _serverTraffic);
            var clientKey = GetKey(_clientTraffic, _keyStore.Buffer.Slice(0, _keySize + _ivSize));
            var serverKey = GetKey(_serverTraffic, _keyStore.Buffer.Slice(_keySize + _ivSize, _keySize + _ivSize));
            return (clientKey, serverKey);
        }

        public (AeadBulkCipher clientKey, AeadBulkCipher serverKey) GenerateApplicationKeys()
        {
            _cryptoProvider.HashProvider.HkdfExtract(_state.CipherSuite.HashType, _secret.Span, new Span<byte>(), _secret.Span);
            var hash = new byte[_hashSize];
            _state.HandshakeHash.FinishHash(hash);
            ExpandLabel(_secret, Label_ClientApplicationTrafficSecret, hash, _clientTraffic);
            ExpandLabel(_secret, Label_ServerApplicationTrafficSecret, hash, _serverTraffic);
            var clientKey = GetKey(_clientTraffic, _keyStore.Buffer.Slice(0, _keySize + _ivSize));
            var serverKey = GetKey(_serverTraffic, _keyStore.Buffer.Slice(_keySize + _ivSize, _keySize + _ivSize));
            return (clientKey, serverKey);
        }

        private AeadBulkCipher GetKey(Buffer<byte> secret, Buffer<byte> keyBuffer)
        {
            ExpandLabel(secret, Label_TrafficIv, new Span<byte>(), keyBuffer.Slice(_keySize));
            ExpandLabel(secret, Label_TrafficKey, new Span<byte>(), keyBuffer.Slice(0, _keySize));
            return _cryptoProvider.BulkCipherProvider.GetCipher<AeadTls13BulkCipher>(_state.CipherSuite.BulkCipherType, keyBuffer);
        }

        public bool ProcessClientFinished(Span<byte> clientBuffer)
        {
            GenerateClientFinishedKey();
            var buffer = new byte[_hashSize];
            _state.HandshakeHash.InterimHash(buffer);
            _cryptoProvider.HashProvider.HmacData(_state.CipherSuite.HashType, _finishedKey.Span, buffer, buffer);
            return Internal.CompareFunctions.ConstantTimeEquals(clientBuffer, buffer);
        }

        public void GenerateServerFinished(Span<byte> buffer)
        {
            GenerateServerFinishedKey();
            _state.HandshakeHash.InterimHash(buffer);
            _cryptoProvider.HashProvider.HmacData(_state.CipherSuite.HashType, _finishedKey.Span, buffer, buffer);
        }

        protected void ExpandLabel(Buffer<byte> secret, Span<byte> label, Span<byte> hash, Buffer<byte> output) =>
            _cryptoProvider.HashProvider.HkdfExpandLabel(_state.CipherSuite.HashType, secret.Span, label, hash, output.Span);

        private void GenerateClientFinishedKey() => _cryptoProvider.HashProvider.HkdfExpandLabel(
            _state.CipherSuite.HashType, _clientTraffic.Span, Label_FinishedKey, new Span<byte>(), _finishedKey.Span);

        private void GenerateServerFinishedKey() => _cryptoProvider.HashProvider.HkdfExpandLabel(
            _state.CipherSuite.HashType, _serverTraffic.Span, Label_FinishedKey, new Span<byte>(), _finishedKey.Span);

        private Buffer<byte> GetBufferSlice(int size)
        {
            var buffer = _remainingStore.Slice(0, size);
            _remainingStore = _remainingStore.Slice(size);
            return buffer;
        }

        public void Dispose()
        {
            _secretStore?.Dispose();
            _secretStore = null;
            _keyStore?.Dispose();
            _keyStore = null;
            GC.SuppressFinalize(this);
        }

        ~SecretSchedule13() => Dispose();
    }
}
