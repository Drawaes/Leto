using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static Interop.BCrypt;

namespace Leto.Tls13.Interop.Windows
{
    internal static class BCryptPropertiesHelper
    {
        internal static int GetObjectLength(SafeBCryptAlgorithmHandle provider)
        {
            return GetIntProperty(provider, BCryptPropertyStrings.BCRYPT_OBJECT_LENGTH);
        }

        internal unsafe static BCRYPT_AUTH_TAG_LENGTHS_STRUCT GetAuthTagLengths(SafeBCryptHandle provider)
        {
            var size = sizeof(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            var output = default(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            int result;
            BCryptGetProperty(provider, BCryptPropertyStrings.BCRYPT_AUTH_TAG_LENGTH, &output, size, out result, 0);
            return output;
        }

        internal static int GetMaxAuthTagLength(SafeBCryptHandle provider)
        {
            return GetAuthTagLengths(provider).dwMaxLength;
        }

        internal static int GetBlockLength(SafeBCryptHandle provider)
        {
            return GetIntProperty(provider, BCryptPropertyStrings.BCRYPT_BLOCK_LENGTH);
        }

        internal static int GetHashLength(SafeBCryptHandle provider)
        {
            return GetIntProperty(provider, BCryptPropertyStrings.BCRYPT_HASH_LENGTH);
        }

        internal static int GetKeySizeInBits(SafeBCryptHandle provider)
        {
            return GetIntProperty(provider, BCryptPropertyStrings.BCRYPT_KEY_LENGTH);
        }

        internal static void SetEccCurveName(SafeBCryptHandle key, string curveName)
        {
            SetStringProperty(key, BCryptPropertyStrings.BCRYPT_ECC_CURVE_NAME, curveName);
        }

        private unsafe static int GetIntProperty(SafeBCryptHandle provider, string property)
        {
            int length;
            int objectSize;
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, &objectSize, 4, out length, 0));
            return objectSize;
        }

        private unsafe static string GetStringProperty(SafeBCryptHandle provider, string property)
        {
            int objectSize;
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, null, 0, out objectSize, 0));
            var buffer = stackalloc byte[objectSize];
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, buffer, objectSize, out objectSize, 0));
            return Marshal.PtrToStringUni((IntPtr)buffer);
        }

        private static void SetStringProperty(SafeBCryptHandle provider, string property, string value)
        {
            ExceptionHelper.CheckReturnCode(
                BCryptSetProperty(provider, property, value, value != null ? (value.Length + 1) * sizeof(char) : 0, 0));
        }

        private unsafe static string[] GetStringArrayProperty(SafeBCryptHandle provider, string property)
        {
            int bufferSize;
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, null, 0, out bufferSize, 0));
            var tempBuffer = stackalloc byte[bufferSize];
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, tempBuffer, bufferSize, out bufferSize, 0));
            var header = Marshal.PtrToStructure<BCRYPT_ECC_CURVE_NAMES>((IntPtr)tempBuffer);
            var returnValues = new string[header.dwEccCurveNames];
            for (var i = 0; i < header.dwEccCurveNames; i++)
            {
                var currentPtr = Unsafe.Read<IntPtr>((void*)IntPtr.Add(header.pEccCurveNames, i * IntPtr.Size));
                returnValues[i] = Marshal.PtrToStringUni(currentPtr);
            }
            return returnValues;
        }

        internal static string[] GetECCurveNameList(SafeBCryptHandle provider)
        {
            return GetStringArrayProperty(provider, BCryptPropertyStrings.BCRYPT_ECC_CURVE_NAME_LIST);
        }

        internal static string GetBlockChainingMode(SafeBCryptHandle provider)
        {
            return GetStringProperty(provider, BCryptPropertyStrings.BCRYPT_CHAINING_MODE);
        }

        internal static void SetBlockChainingMode(SafeBCryptHandle provider, string chainingMode)
        {
            SetStringProperty(provider, BCryptPropertyStrings.BCRYPT_CHAINING_MODE, chainingMode);
        }
    }
}
