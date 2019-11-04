using DigitArc.Lib.Security.JwtTokenValidator.Dto;
using DigitArc.Lib.Security.JwtTokenValidator.Extensions;
using IdentityModel.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

namespace DigitArc.Lib.Security.JwtTokenValidator.Middlewares
{
    public class EnableJwtTokenAuthorization
    {
        private readonly IAuthorizationService _authorizationService;
        private readonly RequestDelegate _next;
        public EnableJwtTokenAuthorization(RequestDelegate next, IAuthorizationService authorizationService)
        {
            this._authorizationService = authorizationService;
            this._next = next;
        }

        public async Task Invoke(HttpContext context, IOptions<EndPointOptions> endpointOptions)
        {
            if (context.User.Identity.IsAuthenticated)
            {
                try
                {
                    if (!AuthenticationHeaderValue.TryParse(context.Request.Headers[HeaderNames.Authorization], out AuthenticationHeaderValue authHeader))
                    {
                        var accessToken = context.User.FindFirst("access_token")?.Value;
                        if (!string.IsNullOrEmpty(accessToken))
                        {
                            authHeader = AuthenticationHeaderValue.Parse($"Bearer {accessToken}");
                        }
                    }

                    AuthorizationOutput authorizationOutput =
                        await this._authorizationService.ValidateAsync(authHeader);
                }
                catch (Exception e)
                {
                    var refreshToken = context.User.FindFirst("refresh_token")?.Value;
                    using (var client = new HttpClient())
                    {
                        var response = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
                        {
                            Address = endpointOptions.Value.TokenEndpoint,
                            ClientId = endpointOptions.Value.ClientId,
                            ClientSecret = endpointOptions.Value.ClientSecret,
                            RefreshToken = refreshToken
                        });
                        
                        var claim = (ClaimsIdentity)context.User.Identity;
                        claim.UpdateClaim(new Claim("access_token", response.AccessToken));
                        claim.UpdateClaim(new Claim("refresh_token", response.RefreshToken));
                        claim.UpdateClaim(new Claim("expires_in", response.ExpiresIn.ToString()));
                    }
                }
            }

            await this._next.Invoke(context);
        }

    }
    public static class EnableJwtTokenAuthorizationExtensions
    {
        public static IApplicationBuilder UseJwtTokenAuthorization(this IApplicationBuilder app)
        {

            app.UseMiddleware<EnableJwtTokenAuthorization>();

            return app;
        }
    }
}
