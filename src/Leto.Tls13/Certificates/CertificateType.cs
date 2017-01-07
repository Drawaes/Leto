using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Certificates
{
    public enum CertificateType
    {
        Ecdsa_secp256r1,
        Ecdsa_secp384r1,
        Ecdsa_secp521r1,
        Rsa,
    }
}