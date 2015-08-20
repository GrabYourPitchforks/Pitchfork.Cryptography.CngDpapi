using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace Pitchfork.Cryptography.CngDpapi
{
    [SuppressUnmanagedCodeSecurity]
    internal static class UnsafeNativeMethods
    {
        private const string NCRYPT_LIB = "ncrypt.dll";

        /*
         * NCRYPT.DLL
         */

        // https://msdn.microsoft.com/en-us/library/windows/desktop/hh706799(v=vs.85).aspx
        [DllImport(NCRYPT_LIB, CallingConvention = CallingConvention.Winapi)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static extern int NCryptCloseProtectionDescriptor(
            [In] IntPtr hDescriptor);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/hh706800(v=vs.85).aspx
        [DllImport(NCRYPT_LIB, CallingConvention = CallingConvention.Winapi)]
        public static extern int NCryptCreateProtectionDescriptor(
            [In, MarshalAs(UnmanagedType.LPWStr)] string pwszDescriptorString,
            [In] ProtectionDescriptorCreationFlags dwFlags,
            [Out] out SafeProtectionDescriptorHandle phDescriptor);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/hh706802(v=vs.85).aspx
        [DllImport(NCRYPT_LIB, CallingConvention = CallingConvention.Winapi)]
        public static extern int NCryptProtectSecret(
            [In] SafeProtectionDescriptorHandle hDescriptor,
            [In] uint dwFlags,
            [In] byte[] pbData,
            [In] uint cbData,
            [In] IntPtr pMemPara,
            [In] IntPtr hWnd,
            [Out] out SafeLocalAllocHandle ppbProtectedBlob,
            [Out] out uint pcbProtectedBlob);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/hh706811(v=vs.85).aspx
        [DllImport(NCRYPT_LIB, CallingConvention = CallingConvention.Winapi)]
        public static extern int NCryptUnprotectSecret(
            [In] IntPtr phDescriptor,
            [In] uint dwFlags,
            [In] byte[] pbProtectedBlob,
            [In] uint cbProtectedBlob,
            [In] IntPtr pMemPara,
            [In] IntPtr hWnd,
            [Out] out SafeLocalAllocHandle ppbData,
            [Out] out uint pcbData);
    }
}
