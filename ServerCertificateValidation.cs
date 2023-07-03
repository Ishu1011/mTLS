using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace clientt
{
    public class ServerCertificateValidation
    {

        public static bool ValidateServerCertificate(HttpRequestMessage message, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            var trustedCACertificates = LoadTrustedCACertificates();

            //To Configure the Certificate Chain validation process and we didn't do any Revocation here
            //And the Verification flag property also we set to Allow Unknown CertificateAuthority

            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                return false;
            }
            var chainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck,
                RevocationFlag = X509RevocationFlag.ExcludeRoot,
                VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority,

            };
            var CertificateChain = new X509Chain();
            CertificateChain.ChainPolicy = chainPolicy;
            CertificateChain.ChainPolicy.ExtraStore.AddRange(trustedCACertificates);
            bool chainIsValid = chain.Build(certificate);


            // Check if the client certificate is valid
            var cetificateIsValid = chainIsValid && (sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors);
            if (cetificateIsValid)
            {
                // Display the thumbprint of the server certificate
                Console.WriteLine("Server Certificate Thumbprint: " + certificate.Thumbprint);
            }

            return cetificateIsValid;



        }
        private static X509Certificate2Collection LoadTrustedCACertificates()
        {
            //Load the trusted CA certificates from the localmachines's trusted root CA Certificate store
            var trustedCAs = new List<X509Certificate2>();
            using (var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                foreach (var certificate in store.Certificates)
                {
                    //Add the Certificate to the list of trustedCAs if it is a CA Certificate
                    if (certificate.Subject.Contains("localhost"))
                    {
                        trustedCAs.Add(certificate);
                    }
                }
            }
            var trustedCACertificates = new X509Certificate2Collection(trustedCAs.ToArray());
            return trustedCACertificates;
        }
    }

}

