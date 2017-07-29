using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static LegacyOpenSsl.Interop.LibCrypto;

namespace LegacyOpenSsl.Interop
{
    public static partial class OpenSsl
    {
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        private unsafe extern static int SSL_CTX_ctrl(SSL_CTX ctx, SSL_CTRL cmd, int larg, void* ptr);

        private enum SSL_CTRL : ushort
        {
            SSL_CTRL_CLEAR_MODE = 78,
            SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB = 79,
            SSL_CTRL_GET_EXTRA_CHAIN_CERTS = 82,
            SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83,
            SSL_CTRL_CHAIN = 88,
            SSL_CTRL_CHAIN_CERT = 89,
            SSL_CTRL_GET_GROUPS = 90,
            SSL_CTRL_SET_GROUPS = 91,
            SSL_CTRL_SET_GROUPS_LIST = 92,
            SSL_CTRL_GET_SHARED_GROUP = 93,
            SSL_CTRL_SET_SIGALGS = 97,
            SSL_CTRL_SET_SIGALGS_LIST = 98,
            SSL_CTRL_CERT_FLAGS = 99,
            SSL_CTRL_CLEAR_CERT_FLAGS = 100,
            SSL_CTRL_SET_CLIENT_SIGALGS = 101,
            SSL_CTRL_SET_CLIENT_SIGALGS_LIST = 102,
            SSL_CTRL_GET_CLIENT_CERT_TYPES = 103,
            SSL_CTRL_SET_CLIENT_CERT_TYPES = 104,
            SSL_CTRL_BUILD_CERT_CHAIN = 105,
            SSL_CTRL_SET_VERIFY_CERT_STORE = 106,
            SSL_CTRL_SET_CHAIN_CERT_STORE = 107,
            SSL_CTRL_GET_PEER_SIGNATURE_NID = 108,
            SSL_CTRL_GET_SERVER_TMP_KEY = 109,
            SSL_CTRL_GET_RAW_CIPHERLIST = 110,
            SSL_CTRL_GET_EC_POINT_FORMATS = 111,
            SSL_CTRL_GET_CHAIN_CERTS = 115,
            SSL_CTRL_SELECT_CURRENT_CERT = 116,
            SSL_CTRL_SET_CURRENT_CERT = 117,
            SSL_CTRL_SET_DH_AUTO = 118,
            DTLS_CTRL_SET_LINK_MTU = 120,
            DTLS_CTRL_GET_LINK_MIN_MTU = 121,
            SSL_CTRL_GET_EXTMS_SUPPORT = 122,
            SSL_CTRL_SET_MIN_PROTO_VERSION = 123,
            SSL_CTRL_SET_MAX_PROTO_VERSION = 124,
            SSL_CTRL_SET_SPLIT_SEND_FRAGMENT = 125,
            SSL_CTRL_SET_MAX_PIPELINES = 126,
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE = 127,
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB = 128,
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG = 129,
        }
    }
}
