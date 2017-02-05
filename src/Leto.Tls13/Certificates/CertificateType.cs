using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Certificates
{
    public enum CertificateType
    {
        anonymous = 0,
        rsa = 1,
        dsa = 2,
        ecdsa = 3,
    }
}