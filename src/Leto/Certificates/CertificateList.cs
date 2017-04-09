using System;
using System.Collections.Generic;
using Leto.Internal;
using static Leto.BufferExtensions;

namespace Leto.Certificates
{
    public class CertificateList
    {
        private List<ICertificate> _certificates = new List<ICertificate>();

        public void AddCertificate(ICertificate certificate) => _certificates.Add(certificate);

        public ICertificate GetCertificate(string host, CertificateType certificateType)
        {
            for (var i = 0; i < _certificates.Count; i++)
            {
                if (host != null)
                {
                    //Need to implement certificates for a specific host
                    throw new NotImplementedException();
                }
                else
                {
                    if (_certificates[i].CertificateType == certificateType)
                    {
                        return _certificates[i];
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.certificate_unobtainable, $"Could not find a certficate for {host} and type {certificateType}");
            return null;
        }

        public ICertificate GetCertificate(string host, SignatureScheme type) => _certificates[0];
        
        public (ICertificate, SignatureScheme) GetCertificate(BigEndianAdvancingSpan buffer)
        {
            buffer = buffer.ReadVector<ushort>();
            while(buffer.Length > 0)
            {
                var scheme = buffer.Read<SignatureScheme>();
                for(var i = 0; i < _certificates.Count;i++)
                {
                    if (_certificates[i].SupportsScheme(scheme))
                    {
                        return (_certificates[i], scheme);
                    }
                }
            }
            Alerts.AlertException.ThrowFailedHandshake("Failed to find a certificate and scheme that matches");
            return (null, SignatureScheme.none);
        }
    }
}
