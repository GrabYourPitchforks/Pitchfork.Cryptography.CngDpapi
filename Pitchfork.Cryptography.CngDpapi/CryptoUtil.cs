using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Pitchfork.Cryptography.CngDpapi
{
    internal static class CryptoUtil
    {
        public static void AssertSafeHandleIsValid(SafeHandle safeHandle)
        {
            if (safeHandle == null || safeHandle.IsInvalid)
            {
                throw new CryptographicException(Res.SafeHandleNotValid);
            }
        }

        public static void AssertSuccess(int ntstatus)
        {
            if (ntstatus != 0)
            {
                throw new CryptographicException(ntstatus);
            }
        }
    }
}
