using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.Certificates.Windows;
using Leto.Tls13.Internal;

namespace Leto.Tls13
{
    public sealed class CertificateList:IDisposable
    {
        private List<ICertificate> _certificates = new List<ICertificate>();
        
        public void AddCertificate(ICertificate certificate)
        {
            _certificates.Add(certificate);
        }
        
        public ICertificate GetCertificate(string host, SignatureScheme type)
        {
            for (int i = 0; i < _certificates.Count; i++)
            {
                //if (_certificates[i].HostName != host && host != null)
                //{
                //    continue;
                //}
                var cert = _certificates[i];
                if (!cert.SupportsSignatureScheme(type))
                {
                    continue;
                }
                return _certificates[i];
            }
            return null;
        }

        public void Dispose()
        {
            foreach(var cert in _certificates)
            {
                cert.Dispose();
            }
            _certificates = null;
            GC.SuppressFinalize(this);
        }

        ~CertificateList()
        {
            Dispose();
        }
    }
}
