using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedule13
    {
        private Server13ConnectionState _state;
        private ICryptoProvider _cryptoProvider;
        private OwnedBuffer<byte> _secretStore;
        private OwnedBuffer<byte> _keyStore;

        public SecretSchedule13(Server13ConnectionState state)
        {
            _state = state;
            _cryptoProvider = state.SecureConnection.Listener.CryptoProvider;
            (_secretStore, _keyStore) = state.SecureConnection.Listener.SecretSchedulePool.GetSecretBuffer();
        }

        public void Dispose()
        {
            _secretStore?.Dispose();
            _secretStore = null;
            _keyStore?.Dispose();
            _keyStore = null;
            GC.SuppressFinalize(this);
        }

        ~SecretSchedule13()
        {
            Dispose();
        }
    }
}
