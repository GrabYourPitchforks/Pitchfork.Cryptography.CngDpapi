using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Pitchfork.Cryptography.CngDpapi;

namespace Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            // First try with DPAPI ("LOCAL=user")
            RunTest("LOCAL=user");

            // Then try with a SID ("SID={my-sid}")
            // If you're running as a domain user you'll need to be able to reach the AD controller
            RunTest($"SID={WindowsIdentity.GetCurrent().User.Value}");
        }

        private static void RunTest(string descriptorString)
        {
            Console.WriteLine($"Trying descriptor '{descriptorString}'.");
            byte[] plaintextBlob = Encoding.UTF8.GetBytes("Hello!");
            using (var protectionDescriptor = new ProtectionDescriptor(descriptorString))
            {
                byte[] protectedBlob = protectionDescriptor.ProtectSecret(plaintextBlob);
                Console.WriteLine("ProtectSecret succeeded.");

                byte[] roundTrippedBlob = ProtectionDescriptor.UnprotectSecret(protectedBlob);
                string roundTrippedString = Encoding.UTF8.GetString(roundTrippedBlob);
                if (roundTrippedString == "Hello!")
                {
                    Console.WriteLine("UnprotectSecret succeeded.");
                } else
                {
                    throw new CryptographicException($"UnprotectSecret failed: Expected 'Hello!' but got '{roundTrippedString}'!");
                }
            }
        }
    }
}
