using Leto.Certificates;
using Microsoft.DotNet.PlatformAbstractions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Leto.OpenSslFacts.Data
{
    public static class Certificates
    {
        public static ICertificate RSACertificate = new ManagedCertificate(new X509Certificate2(Path.Combine(ApplicationEnvironment.ApplicationBasePath, @"Data/TestCert.pfx"), "Test123t"), null);
    }
}
