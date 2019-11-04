using DigitArc.Lib.Security.JwtTokenValidator.Dto;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace DigitArc.Lib.Security.JwtTokenValidator.FilterAttributes
{
    public class JwtTokenValidatorAttribute : FunctionInvocationFilterAttribute
    {
        private readonly IAuthorizationService _authService;

        /// <summary>
        /// Authorize user by the Bearer Token given in the Authorization Header.
        /// In case of success, within the HttpContext, user relevant informations will be added such as userId and email but also valid DeviceIDs for the given user.
        /// In any other case, the request ends up with an exception and will not reach the decorated function. 
        /// </summary>
        /// <param name="stsDiscoveryEndpointEnvironmentKey">The env key to retrieve the stsDiscovery endpoint</param>
        /// <param name="audienceEnvironmentKey">The env key to retrieve the audienceEnvironmentKey</param>
        /// <param name="issuerEnvironmentKey">The env key to retrieve the issuerEnvironmentKey/param>
        public JwtTokenValidatorAttribute(string stsDiscoveryEndpointEnvironmentKey, string audienceEnvironmentKey, string issuerEnvironmentKey)
        {
            this._authService =
                new AuthorizationService(Environment.GetEnvironmentVariable(stsDiscoveryEndpointEnvironmentKey),
                Environment.GetEnvironmentVariable(issuerEnvironmentKey),
                Environment.GetEnvironmentVariable(audienceEnvironmentKey));
        }

        public override async Task OnExecutingAsync(FunctionExecutingContext executingContext, CancellationToken cancellationToken)
        {
            executingContext.Logger.LogInformation("JWT-Token validator executing...");

            HttpRequest httpRequest = (HttpRequest)executingContext.Arguments.First().Value;
            var authHeader = AuthenticationHeaderValue.Parse(httpRequest.Headers[HeaderNames.Authorization]);

            AuthorizationOutput authorizationOutput = await this._authService.ValidateAsync(authHeader);
            executingContext.Logger.LogInformation($"JWT-Token successful validated. Email: {authorizationOutput.Email}, User Roles: {authorizationOutput.ResourceAccess}");
            httpRequest.HttpContext.Items.Add(HttpContextItems.AuthorizationOutput, authorizationOutput);

            await base.OnExecutingAsync(executingContext, cancellationToken);
        }
    }
}
