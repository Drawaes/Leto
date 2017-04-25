﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Principal;
using static Interop.Secur32;

namespace Leto.WindowsAuthentication
{
    public class WindowsAuthFeature : IDisposable, IWindowsAuthFeature
    {
        private static SecurityHandle _credentialsHandle;
        private WindowsHandshake _handshake;

        static WindowsAuthFeature()
        {
            var result = AcquireCredentialsHandle(null, "Negotiate", CredentialsUse.SECPKG_CRED_INBOUND,
                            IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, out _credentialsHandle, out SecurityInteger timeSpan);
            if (result != SEC_RESULT.SEC_E_OK)
            {
                throw new InvalidOperationException();
            }
        }

        public WindowsAuthFeature() => _handshake = new WindowsHandshake(_credentialsHandle);

        public WindowsIdentity Identity { get; set; }

        public void Dispose()
        {
            Identity?.Dispose();
            _handshake?.Dispose();
            Identity = null;
        }

        public string ProcessHandshake(string tokenName, byte[] token) => _handshake.AcceptSecurityToken(tokenName, token);

        public WindowsIdentity GetUser()
        {
            var user = _handshake.User;
            if (user == null)
            {
                return null;
            }
            _handshake.Dispose();
            _handshake = null;
            return user;
        }
    }
}
