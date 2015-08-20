using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Pitchfork.Cryptography.CngDpapi
{
    internal unsafe sealed class SafeLocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        // Called by P/Invoke when returning SafeHandles
        private SafeLocalAllocHandle()
            : base(ownsHandle: true)
        {
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        private void CopyToCore(byte* dest, ulong byteCount)
        {
            bool refAdded = false;
            try
            {
                DangerousAddRef(ref refAdded);
                Buffer.MemoryCopy(
                    source: (void*)DangerousGetHandle(),
                    destination: dest,
                    destinationSizeInBytes: byteCount,
                    sourceBytesToCopy: byteCount);
            }
            finally
            {
                if (refAdded)
                {
                    DangerousRelease();
                }
            }
        }

        // Do not provide a finalizer - SafeHandle's critical finalizer will
        // call ReleaseHandle for you.

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle); // actually calls LocalFree
            return true;
        }

        public byte[] ToByteArray(uint byteCount)
        {
            byte[] retVal = new byte[byteCount];
            if (byteCount != 0)
            {
                fixed (byte* pRetVal = retVal) // guaranteed non-null since array is of length > 0
                {
                    CopyToCore(pRetVal, byteCount);
                }
            }
            return retVal;
        }
    }
}
