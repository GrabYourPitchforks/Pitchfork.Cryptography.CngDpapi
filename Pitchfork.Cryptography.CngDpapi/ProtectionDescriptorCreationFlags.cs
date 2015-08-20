using System;

namespace Pitchfork.Cryptography.CngDpapi
{
    /// <summary>
    /// Controls how a <see cref="ProtectionDescriptor"/> is created.
    /// </summary>
    /// <remarks>
    /// These flags correspond to the <em>dwFlags</em> parameter of
    /// <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/hh706800(v=vs.85).aspx">NCryptCreateProtectionDescriptor</a>.
    /// </remarks>
    [Flags]
    public enum ProtectionDescriptorCreationFlags
    {
        /// <summary>
        /// Indicates that the provided descriptor string is fully self-contained and is not a
        /// named reference to a descriptor string stored in the registry.
        /// </summary>
        None = 0,

        /// <summary>
        /// Indicates that the provided descriptor string is a name registered by
        /// <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/hh706804(v=vs.85).aspx">NCryptRegisterProtectionDescriptorName</a>.
        /// </summary>
        NamedDescriptor = 0x00000001,

        /// <summary>
        /// Indicates that the provided named descriptor string is stored in the HKEY_LOCAL_MACHINE
        /// registry rather than the HKEY_CURRENT_USER registry.
        /// </summary>
        UseMachineRegistry = 0x00000020,
    }
}
