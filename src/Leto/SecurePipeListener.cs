using Leto.Certificates;
using Leto.ConnectionStates.SecretSchedules;
using Leto.Handshake.Extensions;
using Leto.Sessions;
using System;
using System.IO.Pipelines;
using System.Threading.Tasks;

namespace Leto
{
    public abstract class SecurePipeListener : IDisposable
    {
        private ApplicationLayerProtocolProvider _alpnProvider;
        private SecureRenegotiationProvider _secureRenegotiationProvider;
        private CertificateList _certificateList = new CertificateList();
        private HostNameProvider _hostNameProvider = new HostNameProvider();
        private SecretSchedulePool _secretPool;
        private PipeFactory _pipeFactory;
        private bool _factoryOwned;

        protected SecurePipeListener(ICertificate certificate, PipeFactory pipeFactory = null)
        {
            if (pipeFactory == null)
            {
                _factoryOwned = true;
                _pipeFactory = new PipeFactory();
            }
            else
            {
                _pipeFactory = pipeFactory;
            }
            _secretPool = new SecretSchedulePool();
            _certificateList.AddCertificate(certificate);
            _alpnProvider = new ApplicationLayerProtocolProvider(true, ApplicationLayerProtocolType.Http1_1);
            _secureRenegotiationProvider = new SecureRenegotiationProvider();
        }

        public abstract ICryptoProvider CryptoProvider { get; set; }
        public abstract ISessionProvider SessionProvider { get; }
        public ApplicationLayerProtocolProvider AlpnProvider => _alpnProvider;
        public SecureRenegotiationProvider SecureRenegotiationProvider => _secureRenegotiationProvider;
        public CertificateList CertificateList => _certificateList;
        public SecretSchedulePool SecretSchedulePool => _secretPool;
        public HostNameProvider HostNameProvider => _hostNameProvider;

        public Task<SecurePipeConnection> CreateConnection(IPipeConnection connection)
        {
            var secureConnection = new SecurePipeConnection(_pipeFactory, connection, this);
            return secureConnection.HandshakeAwaiter;
        }

        public void Dispose() => Dispose(false);
        
        protected virtual void Dispose(bool disposing)
        {
            if (_factoryOwned)
            {
                _pipeFactory?.Dispose();
                _pipeFactory = null;
            }
            _secretPool?.Dispose();
            _secretPool = null;
            GC.SuppressFinalize(this);
        }

        ~SecurePipeListener() => Dispose(true);
    }
}
