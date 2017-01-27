using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Leto.Tls13.Internal;

namespace Leto.Tls13.Certificates.Windows
{
    public class CertificateProvider
    {
        public ICertificate LoadCertificate(X509Certificate2 certificate)
        {
            return LoadCertificate(certificate, new X509Certificate2Collection());
        }

        public ICertificate LoadCertificate(X509Certificate2 cert, X509Certificate2Collection chainCertificates)
        {
            var rsaKey = cert.GetRSAPrivateKey();
            
            if(rsaKey != null)
            {
                return new RsaCertificate(cert, chainCertificates);
            }
            var ecdsaKey = cert.GetECDsaPrivateKey();
            if(ecdsaKey != null)
            {
                return new EcdsaCertificate(cert, chainCertificates);
            }
            throw new NotSupportedException();
        }
        
        public ICertificate LoadCertificateFromStore(string thumbprint, bool pullChain, StoreLocation storeLocation = StoreLocation.CurrentUser, StoreName storeName = StoreName.My)
        {
            using (var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.MaxAllowed);
                var certList = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true);
                if (certList.Count != 1)
                {
                    ExceptionHelper.ThrowException(new ArgumentOutOfRangeException(nameof(thumbprint)));
                }
                var cert = certList[0];
                var chain = new X509Chain();
                var chainCertificates = new X509Certificate2Collection();
                if (chain.Build(cert))
                {
                    //We have a chain so we can reverse the chain (we need to send the certificates with the 
                    //root last for TLS
                    for (int i = chain.ChainElements.Count - 1; i > -1; i--)
                    {
                        chainCertificates.Add(chain.ChainElements[i].Certificate);
                    }
                }
                return LoadCertificate(cert, chainCertificates);
            }
        }
    }
}
