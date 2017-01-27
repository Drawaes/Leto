using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Handshake;
using Leto.Tls13.State;

namespace Leto.Tls13.Sessions
{
    public class ResumptionProvider
    {
        private ResumptionKey[] _keyset;
        private int _historySize;
        private int _currentIndex;
        private int _currentInsertPoint;
        private CryptoProvider _provider;

        public ResumptionProvider(int historySize, CryptoProvider provider)
        {
            _historySize = historySize;
            _keyset = new ResumptionKey[_historySize];
            _provider = provider;
            GenerateResumptionKey();
        }
        
        public void AddNewKey(DateTime keyExpiry, DateTime keyActivated, ResumptionKey newKey)
        {
            lock (_keyset)
            {
                _currentInsertPoint++;
                _keyset[_currentInsertPoint % _historySize] = newKey;
                if(keyActivated < DateTime.UtcNow)
                {
                    _currentIndex = _currentInsertPoint;
                }
            }
        }

        public void GenerateSessionTicket(ref WritableBuffer writer, IConnectionState state)
        {
            var key = _keyset[_currentIndex];
            key.WriteSessionKey(ref writer, state);
        }

        public unsafe void GenerateResumptionKey()
        {
            var timestamp = DateTime.UtcNow.ToBinary();
            var code = stackalloc long[2];
            _provider.FillWithRandom(code, 16);
            code[0] = code[0] ^ timestamp;
            var key = new byte[32];
            var nounceBase = new byte[12];
            _provider.FillWithRandom(key);
            _provider.FillWithRandom(nounceBase);

            var newKey = new ResumptionKey(code[0], code[1], key, nounceBase);
            AddNewKey(DateTime.UtcNow.AddHours(4), DateTime.UtcNow.AddHours(-1), newKey);
        }

        public bool TryToResume(long serviceId, long keyId, ReadableBuffer identity, IConnectionStateTls13 state)
        {
            for(int i = 0; i < _keyset.Length;i++)
            {
                var key = _keyset[i];
                if(key == null)
                {
                    continue;
                }
                if(key.ServiceId != serviceId || key.KeyId != keyId)
                {
                    continue;
                }
                state.PskIdentity = 0;
                key.DecryptSession(ref identity, state);
                return true;
            }
            return false;
        }

        public void RegisterSessionTicket(ReadableBuffer buffer)
        {
            //slice off the head first
            buffer = buffer.Slice(HandshakeProcessor.HandshakeHeaderSize);
            uint ticketAge, ageRandom;
            buffer = buffer.SliceBigEndian(out ticketAge);
            buffer = buffer.SliceBigEndian(out ageRandom);
            var ticketData = BufferExtensions.SliceVector<ushort>(ref buffer);
            if(buffer.Length > 0)
            {
                //Extensions
                buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
                if(buffer.Length > 0)
                {
                    //seems we can resume data
                    ExtensionType type;
                    buffer = buffer.SliceBigEndian(out type);
                    if(type != ExtensionType.ticket_early_data_info)
                    {
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter,"Early session ticket received had an invalid extension");
                    }

                }
            }
        }
    }
}
