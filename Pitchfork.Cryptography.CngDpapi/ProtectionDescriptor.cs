using System;

namespace Pitchfork.Cryptography.CngDpapi
{
    /// <summary>
    /// Provides a facility to protect and unprotect data given a descriptor of the parties who should
    /// be able to unprotect that data.
    /// </summary>
    public sealed class ProtectionDescriptor : IDisposable
    {
        // from ncrypt.h
        private const uint NCRYPT_SILENT_FLAG = 0x00000040;

        // a non-empty array that can be passed to p/invoke to avoid the auto-conversion from empty array to null pointer
        private static readonly byte[] _dummyBuffer = new byte[1];

        private readonly SafeProtectionDescriptorHandle _descriptorHandle;

        /// <summary>
        /// Initializes a new instance of <see cref="ProtectionDescriptor"/> given a descriptor string.
        /// </summary>
        /// <param name="descriptorString">A protection descriptor rule string.</param>
        public ProtectionDescriptor(string descriptorString)
            : this(descriptorString, ProtectionDescriptorCreationFlags.None)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ProtectionDescriptor"/> given a descriptor string
        /// and information on how to interpret that string.
        /// </summary>
        /// <param name="descriptorString">A protection descriptor rule string or a registered display
        /// name for a descriptor rule string stored in the registry.</param>
        /// <param name="creationFlags">Flags which control how <paramref name="descriptorString"/> is
        /// to be interpreted.</param>
        public ProtectionDescriptor(string descriptorString, ProtectionDescriptorCreationFlags creationFlags)
        {
            // param checks
            if (descriptorString == null)
            {
                throw new ArgumentNullException(nameof(descriptorString));
            }
            if ((creationFlags & (ProtectionDescriptorCreationFlags.NamedDescriptor | ProtectionDescriptorCreationFlags.UseMachineRegistry)) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(creationFlags));
            }

            // handle creation
            int ntstatus = UnsafeNativeMethods.NCryptCreateProtectionDescriptor(
                pwszDescriptorString: descriptorString,
                dwFlags: creationFlags,
                phDescriptor: out _descriptorHandle);
            CryptoUtil.AssertSuccess(ntstatus);
            CryptoUtil.AssertSafeHandleIsValid(_descriptorHandle);
        }

        /// <summary>
        /// Disposes of this object.
        /// </summary>
        public void Dispose()
        {
            _descriptorHandle.Dispose();
        }

        /// <summary>
        /// Protects a blob of data to this descriptor.
        /// </summary>
        /// <param name="data">The data to protect.</param>
        /// <returns>The protected form of <paramref name="data"/>. Use <see cref="UnprotectSecret(byte[])"/>
        /// to unprotect this blob.</returns>
        public byte[] ProtectSecret(byte[] data)
        {
            // param checks
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            SafeLocalAllocHandle localAllocHandle;
            uint cbProtectedBlob;
            int ntstatus = UnsafeNativeMethods.NCryptProtectSecret(
                hDescriptor: _descriptorHandle,
                dwFlags: NCRYPT_SILENT_FLAG,
                pbData: (data.Length != 0) ? data : _dummyBuffer, // avoid passing null pointers
                cbData: (uint)data.Length,
                pMemPara: IntPtr.Zero,
                hWnd: IntPtr.Zero,
                ppbProtectedBlob: out localAllocHandle,
                pcbProtectedBlob: out cbProtectedBlob);
            CryptoUtil.AssertSuccess(ntstatus);
            CryptoUtil.AssertSafeHandleIsValid(localAllocHandle);

            using (localAllocHandle)
            {
                return localAllocHandle.ToByteArray(cbProtectedBlob);
            }
        }

        /// <summary>
        /// Unprotects a blob of data that was protected by <see cref="ProtectSecret(byte[])"/>.
        /// </summary>
        /// <param name="protectedSecret">The blob to unprotect.</param>
        /// <returns>The unprotected form of <paramref name="protectedSecret"/>.</returns>
        public static byte[] UnprotectSecret(byte[] protectedSecret)
        {
            // param checks
            if (protectedSecret == null)
            {
                throw new ArgumentNullException(nameof(protectedSecret));
            }

            SafeLocalAllocHandle localAllocHandle;
            uint cbProtectedBlob;
            int ntstatus = UnsafeNativeMethods.NCryptUnprotectSecret(
                phDescriptor: IntPtr.Zero,
                dwFlags: NCRYPT_SILENT_FLAG,
                pbProtectedBlob: (protectedSecret.Length != 0) ? protectedSecret : _dummyBuffer, // avoid passing null pointers
                cbProtectedBlob: (uint)protectedSecret.Length,
                pMemPara: IntPtr.Zero,
                hWnd: IntPtr.Zero,
                ppbData: out localAllocHandle,
                pcbData: out cbProtectedBlob);
            CryptoUtil.AssertSuccess(ntstatus);
            CryptoUtil.AssertSafeHandleIsValid(localAllocHandle);

            using (localAllocHandle)
            {
                return localAllocHandle.ToByteArray(cbProtectedBlob);
            }
        }
    }
}
