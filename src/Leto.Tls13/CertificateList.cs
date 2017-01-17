using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.Certificates.OpenSsl11;

namespace Leto.Tls13
{
    public sealed class CertificateList:IDisposable
    {
        private List<ICertificate> _certificates = new List<ICertificate>();
        private ICertificateProvider _certificateProvider = new CertificateProvider();

        public void AddCertificate(X509Certificate2 certificate)
        {
            _certificates.Add(_certificateProvider.LoadCertificate(certificate));
        }

        public void AddCertificateFile(string filename, string password)
        {
            _certificates.Add(_certificateProvider.LoadPfx12(filename,password));
        }

        public void AddPEMCertificate(string certificate, string privateKey)
        {
            _certificates.Add(_certificateProvider.LoadCertificate(certificate, privateKey));
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
