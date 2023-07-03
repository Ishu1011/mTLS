using CertificateAuthtentication.Middleware;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.Configure<KestrelServerOptions>(option =>
{
    option.ConfigureHttpsDefaults(option =>
        option.ClientCertificateMode = ClientCertificateMode.RequireCertificate);
});

var serverCertificate = new X509Certificate2("D:\\cert\\server.pfx", "jin7dance");
var thumbprint = serverCertificate.Thumbprint;

// Print the thumbprint to the console
Console.WriteLine("Server Certificate Thumbprint: " + thumbprint);


var host = Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(webBuiler =>
{
    webBuiler.UseKestrel(options =>
    {
        options.ListenAnyIP(5001, listenoption =>
        {
            listenoption.UseHttps(serverCertificate);

        });
    });

});

// Print the thumbprint to the console
Console.WriteLine("Server Certificate Thumbprint: " + thumbprint);
builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseClientCertificateMiddleware();
app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
