using System;
using System.Collections.Generic;
using System.Text;
using Leto.Handshake.Extensions;
using Leto.Certificates;

namespace Leto.OpenSsl11
{
    public class OpenSslSecurePipeListener : ISecurePipeListener
    {
        private ICryptoProvider _cryptoProvider;
        private ApplicationLayerProtocolProvider _alpnProvider;
        private SecureRenegotiationProvider _secureRenegotiationProvider;
        private CertificateList _certificateList = new CertificateList();

        public OpenSslSecurePipeListener(ICertificate certificate)
        {
            _certificateList.AddCertificate(certificate);
            _cryptoProvider = new OpenSslCryptoProvider();
            _alpnProvider = new ApplicationLayerProtocolProvider();
            _secureRenegotiationProvider = new SecureRenegotiationProvider();
        }

        public CertificateList CertificateList => _certificateList;
        public ICryptoProvider CryptoProvider => _cryptoProvider;
        public ApplicationLayerProtocolProvider AlpnProvider => _alpnProvider;
        public SecureRenegotiationProvider SecureRenegotiationProvider => _secureRenegotiationProvider;
    }
}
