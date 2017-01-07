using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Certificates;
using Leto.Tls13.Handshake;
using Leto.Tls13.Hash;
using Leto.Tls13.KeyExchange;

namespace Leto.Tls13.State
{
    public class ConnectionState
    {
        private StateType _state = StateType.None;
        private byte[] _derivedSecret;
        private KeySchedule _keySchedule;
        private CertificateList _certificateList;
        private ManualResetEvent _resetEvent = new ManualResetEvent(true);

        public ConnectionState(CryptoProvider provider, CertificateList certificateList)
        {
            _certificateList = certificateList;
            CryptoProvider = provider;
        }

        public IKeyShareInstance KeyShare { get; set; }
        public IHashInstance HandshakeHash { get; set; }
        public CryptoProvider CryptoProvider { get; set; }
        public IBulkCipherInstance ReadKey { get; set; }
        public IBulkCipherInstance WriteKey { get; set; }
        public CertificateList CertificateList => _certificateList;
        public CipherSuite CipherSuite { get; internal set; }
        public StateType State => _state;
        public ushort Version { get; internal set; }
        public ICertificate Certificate { get; internal set; }
        public ManualResetEvent ResetEvent => _resetEvent;

        public SignatureScheme SignatureScheme { get; internal set; }

        internal void StartHandshakeHash(ReadableBuffer readable)
        {
            HandshakeHash = CryptoProvider.HashProvider.GetHashInstance(CipherSuite.HashType);
            HandshakeHash.HashData(readable);
        }

        public void SetState(StateType state)
        {
            _state = state;
           //switch(state)
           // {
           //     case StateType.SendHelloRetry:
           //         if(_state == StateType.None)
           //         {
           //             _state = state;
           //             return;
           //         }
           //         Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
           //         break;
           //     case StateType.SendServerHello:
           //         if(_state == StateType.None || _state == StateType.WaitHelloRetry)
           //         {
           //             _state = state;
           //             return;
           //         }
           //         Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
           //         break;
                
           //     default:
           //         Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
           //         break;
           // }
        }

        public bool TryToDoAnyWriters(ref WritableBuffer writer)
        {
            _resetEvent.WaitOne();
            switch (_state)
            {
                case StateType.SendHelloRetry:
                    Hello.SendHelloRetry(ref writer, this);
                    _state = StateType.WaitHelloRetry;
                    _resetEvent.Reset();
                    return false;
                case StateType.SendServerHello:
                    WriteHandshake(ref writer, HandshakeType.server_hello, Hello.SendServerHello);
                    _state = StateType.SendServerFlightOne;
                    _resetEvent.Reset();
                    return true;
                case StateType.SendServerFlightOne:
                    GenerateHandshakeKeys();
                    ServerHandshake.SendFlightOne(ref writer, this);
                    _resetEvent.Reset();
                    _state = StateType.SendServerCertificate;
                    return true;
                case StateType.SendServerCertificate:
                    ServerHandshake.SendServerCertificate(ref writer, this);
                    _state = StateType.WaitClientFlightOne;
                    return false;
            }
            return false;
        }

        private unsafe void GenerateHandshakeKeys()
        {
            _keySchedule = new KeySchedule(CipherSuite, CryptoProvider);
            _keySchedule.SetDheDerivedValue(KeyShare.DeriveSecret());
            KeyShare = null;
            var hash = stackalloc byte[HandshakeHash.HashSize];
            var span = new Span<byte>(hash, HandshakeHash.HashSize);
            HandshakeHash.InterimHash(hash, HandshakeHash.HashSize);
            _keySchedule.GenerateHandshakeTrafficKeys(span, this);
        }

        public void WriteHandshake(ref WritableBuffer writer, HandshakeType handshakeType, Func<WritableBuffer, ConnectionState, WritableBuffer> contentWriter)
        {
            writer.WriteBigEndian(handshakeType);
            BufferExtensions.WriteVector24Bit(ref writer, contentWriter, this);
            HandshakeHash.HashData(writer.AsReadableBuffer());
        }
    }
}
