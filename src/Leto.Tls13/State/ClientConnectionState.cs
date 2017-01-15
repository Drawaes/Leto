using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Certificates;
using Leto.Tls13.Handshake;
using Leto.Tls13.Hash;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.Sessions;

namespace Leto.Tls13.State
{
    public class ClientConnectionState : IConnectionState
    {
        private SecurePipelineListener _securePipelineListener;
        private Signal _dataForCurrentScheduleSent = new Signal(Signal.ContinuationMode.Synchronous);
        private Signal _waitForHandshakeToChangeSchedule = new Signal(Signal.ContinuationMode.Synchronous);
        private byte[] _helloBuffer;
        private IBulkCipherInstance _writeKey;
        private IBulkCipherInstance _readKey;

        public ClientConnectionState(SecurePipelineListener securePipelineListener)
        {
            State = StateType.SendClientHello;
            _securePipelineListener = securePipelineListener;
            Version = 0x7f00 | 18;
        }

        public ICertificate Certificate { get; set; }
        public CertificateList CertificateList => _securePipelineListener.CertificateList;
        public CipherSuite CipherSuite { get; set; }
        public CryptoProvider CryptoProvider => _securePipelineListener.CryptoProvider;
        public Signal DataForCurrentScheduleSent => _dataForCurrentScheduleSent;
        public IBulkCipherInstance EarlyDataKey { get; set; }
        public IHashInstance HandshakeHash { get; set; }
        public KeySchedule KeySchedule { get; set; }
        public IKeyshareInstance KeyShare { get; set; }
        public SecurePipelineListener Listener => _securePipelineListener;
        public int PskIdentity { get; set; }
        public PskKeyExchangeMode PskKeyExchangeMode { get; set; }
        public IBulkCipherInstance ReadKey => _readKey;
        public ResumptionProvider ResumptionProvider => Listener.ResumptionProvider;
        public string ServerName { get; set; }
        public SignatureScheme SignatureScheme { get; set; }
        public StateType State { get; set; }
        public ushort Version { get; set; }
        public IBulkCipherInstance WriteKey => _writeKey;
        public bool EarlyDataSupported { get; set; }

        public async Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe)
        {
            switch (State)
            {
                case StateType.WaitServerHello:
                    if (handshakeMessageType == HandshakeType.server_hello)
                    {
                        Hello.ReadServerHello(buffer, this);
                        GenerateHandshakeKeys();
                        State = StateType.WaitEncryptedExtensions;
                        return;
                    }
                    break;
                case StateType.WaitEncryptedExtensions:
                    if (handshakeMessageType == HandshakeType.encrypted_extensions)
                    {
                        HandshakeContext(buffer);
                        State = StateType.WaitServerVerification;
                        return;
                    }
                    break;
                case StateType.WaitServerVerification:
                    if (handshakeMessageType == HandshakeType.certificate)
                    {
                        Handshake.Certificates.ReadCertificates(buffer, Listener);
                        HandshakeContext(buffer);
                        return;
                    }
                    if (handshakeMessageType == HandshakeType.certificate_verify)
                    {
                        HandshakeContext(buffer);
                        State = StateType.WaitServerFinished;
                        return;
                    }
                    break;
                case StateType.WaitServerFinished:
                    if (handshakeMessageType == HandshakeType.finished)
                    {
                        HandshakeContext(buffer);
                        var hash = new byte[HandshakeHash.HashSize];
                        HandshakeHash.InterimHash(hash);
                        var writer = pipe.Alloc();
                        ServerHandshake.ServerFinished(ref writer, this, KeySchedule.GenerateClientFinishedKey());
                        _dataForCurrentScheduleSent.Reset();
                        await writer.FlushAsync();
                        await _dataForCurrentScheduleSent;
                        GenerateApplicationKeys(hash);
                        KeySchedule.GenerateResumptionSecret();
                        HandshakeHash.Dispose();
                        HandshakeHash = null;
                        State = StateType.HandshakeComplete;
                        return;
                    }
                    break;
                case StateType.HandshakeComplete:
                    if (handshakeMessageType == HandshakeType.new_session_ticket)
                    {
                        Listener.ResumptionProvider.RegisterSessionTicket(buffer);
                        return;
                    }
                    break;
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
        }

        private unsafe void GenerateApplicationKeys(byte[] hash)
        {
            KeySchedule.GenerateMasterSecret(hash);
        }

        public void HandshakeContext(ReadableBuffer readable)
        {
            HandshakeHash?.HashData(readable);
        }

        public void StartHandshake(ref WritableBuffer writer)
        {
            this.WriteHandshake(ref writer, HandshakeType.client_hello, Hello.WriteClientHello);
            _helloBuffer = writer.AsReadableBuffer().ToArray();
            State = StateType.WaitServerHello;
        }

        public void StartHandshakeHash(ReadableBuffer readable)
        {
            _dataForCurrentScheduleSent.Set();
            HandshakeHash = CryptoProvider.HashProvider.GetHashInstance(CipherSuite.HashType);
            HandshakeHash.HashData(_helloBuffer);
            _helloBuffer = null;
            HandshakeHash.HashData(readable);
        }

        private unsafe void GenerateHandshakeKeys()
        {
            if (KeySchedule == null)
            {
                KeySchedule = Listener.KeyScheduleProvider.GetKeySchedule(this);
            }
            KeySchedule.SetDheDerivedValue(KeyShare);
            var hash = stackalloc byte[HandshakeHash.HashSize];
            var span = new Span<byte>(hash, HandshakeHash.HashSize);
            HandshakeHash.InterimHash(hash, HandshakeHash.HashSize);
            KeySchedule.GenerateHandshakeTrafficSecrets(span);
            _writeKey = KeySchedule.GenerateServerHandshakeKey();
            if (PskIdentity == -1 || !EarlyDataSupported)
            {
                _readKey?.Dispose();
                _readKey = KeySchedule.GenerateClientHandshakeKey();
            }
        }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        public void HandleAlertMessage(ReadableBuffer readable)
        {
            throw new NotImplementedException();
        }

        ~ClientConnectionState()
        {
            Dispose();
        }
    }
}
