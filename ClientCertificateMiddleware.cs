using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CertificateAuthtentication.Middleware
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class ClientCertificateMiddleware
    {
        private readonly RequestDelegate _next;


        public ClientCertificateMiddleware(RequestDelegate next)
        {
            _next = next;
            
        }

        public async Task Invoke(HttpContext httpContext)
        {

            var ClientCertificate = httpContext.Connection.ClientCertificate;
            if (ClientCertificate == null)
            {
                return;
            }
            if (DateTime.Now > ClientCertificate.NotAfter || DateTime.Now < ClientCertificate.NotBefore) 
            {
               
                return; 
            }

            using(var trustStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
            {
                trustStore.Open(OpenFlags.ReadOnly);
                var trustedCAs = trustStore.Certificates;

                bool Isvalid = ValidateCertificate(ClientCertificate, trustedCAs);
                if (!Isvalid)
                {
                    httpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    return;

                }
                await _next(httpContext).ConfigureAwait(false);
            }


        }

        private bool ValidateCertificate(X509Certificate2 clientCert, X509Certificate2Collection trustedCAs)
        {
            var chain = new X509Chain();
            chain.ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.Online,
                VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
            };

            var isValid = chain.Build(clientCert);

            if (!isValid)
            {
                
                return false;
            }

            foreach (var chainElement in chain.ChainElements)
            {
                if (trustedCAs.Contains(chainElement.Certificate))
                {
                    return true;
                }
            }

            
            return false;
        }

    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class ClientCertificateMiddlewareExtensions
    {
        public static IApplicationBuilder UseClientCertificateMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ClientCertificateMiddleware>();
        }
    }
}
