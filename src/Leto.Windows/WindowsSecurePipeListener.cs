using System;
using System.Collections.Generic;
using System.Text;
using Leto.Certificates;
using Leto.ConnectionStates.SecretSchedules;
using Leto.Handshake.Extensions;

namespace Leto.Windows
{
    public class WindowsSecurePipeListener : ISecurePipeListener
    {
        private ICryptoProvider _cryptoProvider;
        private ApplicationLayerProtocolProvider _alpnProvider;
        private SecureRenegotiationProvider _secureRenegotiationProvider;
        private CertificateList _certificateList = new CertificateList();
        private SecretSchedulePool _secretPool;

        public WindowsSecurePipeListener(ICertificate certificate)
        {
            _secretPool = new SecretSchedulePool();
            _certificateList.AddCertificate(certificate);
            _cryptoProvider = new WindowsCryptoProvider();
            _alpnProvider = new ApplicationLayerProtocolProvider();
            _secureRenegotiationProvider = new SecureRenegotiationProvider();
        }

        public ICryptoProvider CryptoProvider => _cryptoProvider;
        public ApplicationLayerProtocolProvider AlpnProvider => _alpnProvider;
        public SecureRenegotiationProvider SecureRenegotiationProvider => _secureRenegotiationProvider;
        public CertificateList CertificateList => _certificateList;
        public SecretSchedulePool SecretSchedulePool => _secretPool;
    }
}
