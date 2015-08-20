using System;
using System.Runtime.InteropServices;

namespace Pitchfork.Cryptography.CngDpapi
{
    internal sealed class SafeProtectionDescriptorHandle : SafeHandle
    {
        // Called by P/Invoke when returning SafeHandles
        private SafeProtectionDescriptorHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        // Do not provide a finalizer - SafeHandle's critical finalizer will
        // call ReleaseHandle for you.

        public override bool IsInvalid => (handle == IntPtr.Zero);

        protected override bool ReleaseHandle()
        {
            return (UnsafeNativeMethods.NCryptCloseProtectionDescriptor(handle) == 0);
        }
    }
}
