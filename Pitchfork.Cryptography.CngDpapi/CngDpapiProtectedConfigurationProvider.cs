using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using ProtectionDescriptorClass = Pitchfork.Cryptography.CngDpapi.ProtectionDescriptor;

namespace Pitchfork.Cryptography.CngDpapi
{
    /// <summary>
    /// Provides a <see cref="ProtectedConfigurationProvider"/> object that uses
    /// Windows CNG DPAPI to encrypt and decrypt configuration data.
    /// </summary>
    public sealed class CngDpapiProtectedConfigurationProvider : ProtectedConfigurationProvider
    {
        /// <summary>
        /// The protection descriptor string that <see cref="Encrypt(XmlNode)"/> will
        /// use to protect data.
        /// </summary>
        public string ProtectionDescriptor { get; private set; }

        /// <summary>
        /// Decrypts the provided data which was previously encrypted
        /// using <see cref="Encrypt(XmlNode)"/>.
        /// </summary>
        /// <param name="encryptedNode">The data to decrypt.</param>
        /// <returns>The decrypted form of the input data.</returns>
        public override XmlNode Decrypt(XmlNode encryptedNode)
        {
            if (encryptedNode == null)
            {
                throw new ArgumentNullException(nameof(encryptedNode));
            }

            // convert to usable type and extract protected payload

            XElement encryptedElement = XmlNodeToXElement(encryptedNode);
            string protectedBase64 = null;
            if (encryptedElement.Name == "EncryptedData")
            {
                protectedBase64 = encryptedElement.Element("CipherData")?.Element("CipherValue")?.Value;
            }

            if (String.IsNullOrWhiteSpace(protectedBase64))
            {
                throw new ConfigurationErrorsException("The provided node is malformed.");
            }

            // unprotect the data

            byte[] protectedData = Convert.FromBase64String(protectedBase64);
            byte[] unprotectedData = ProtectionDescriptorClass.UnprotectSecret(protectedData);
            string unprotectedXml = Encoding.UTF8.GetString(unprotectedData);

            // turn this back into an XML doc

            XmlDocument xmlDocument = new XmlDocument()
            {
                PreserveWhitespace = true
            };
            xmlDocument.LoadXml(unprotectedXml);
            return xmlDocument.DocumentElement;
        }

        /// <summary>
        /// Encrypts the provided data using the descriptor string specified
        /// by <see cref="ProtectionDescriptor"/>.
        /// </summary>
        /// <param name="node">The data to encrypt.</param>
        /// <returns>The encrypted form of the input data.</returns>
        public override XmlNode Encrypt(XmlNode node)
        {
            if (node == null)
            {
                throw new ArgumentNullException(nameof(node));
            }

            // precondition checks

            if (String.IsNullOrWhiteSpace(ProtectionDescriptor))
            {
                throw new InvalidOperationException("The ProtectionDescriptor property has not been initialized.");
            }

            // protect the data

            byte[] unprotectedData = Encoding.UTF8.GetBytes(node.OuterXml);
            byte[] protectedData = new ProtectionDescriptorClass(ProtectionDescriptor).ProtectSecret(unprotectedData);
            
            // and turn it into the correct data format

            return XElementToXmlNode(
                new XElement("EncryptedData",
                    new XComment($"Payload protected to protection descriptor '{ProtectionDescriptor}'"),
                    new XElement("CipherData",
                        new XElement("CipherValue", Convert.ToBase64String(protectedData)))));
        }

        /// <summary>
        /// Initializes the provider.
        /// </summary>
        /// <param name="name">The friendly name of the provider.</param>
        /// <param name="config">A collection of name/value pairs representing
        /// provider-specific attributes.</param>
        public override void Initialize(string name, NameValueCollection config)
        {
            base.Initialize(name, config);

            // read <add protectionDescriptor="..." />
            ProtectionDescriptor = config["protectionDescriptor"];
            if (String.IsNullOrWhiteSpace(ProtectionDescriptor))
            {
                throw new ConfigurationErrorsException("The 'protectionDescriptor' attribute is missing or is empty.");
            }

            config.Remove("protectionDescriptor");
            if (config.Count > 0)
            {
                throw new ConfigurationErrorsException($"Unrecognized attribute '{config.GetKey(0)}'.");
            }
        }

        /// <summary>
        /// Converts an <see cref="XElement"/> to an <see cref="XmlNode"/>.
        /// </summary>
        private static XmlNode XElementToXmlNode(XElement element)
        {
            using (var reader = element.CreateReader())
            {
                XmlDocument document = new XmlDocument();
                document.Load(reader);
                return document.DocumentElement;
            }
        }

        /// <summary>
        /// Converts an <see cref="XmlNode"/> to an <see cref="XElement"/>.
        /// </summary>
        private static XElement XmlNodeToXElement(XmlNode node)
        {
            return XElement.Parse(node.OuterXml);
        }
    }
}
