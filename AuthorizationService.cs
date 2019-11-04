using DigitArc.Lib.Security.JwtTokenValidator.Dto;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace DigitArc.Lib.Security.JwtTokenValidator
{
    public class AuthorizationService : IAuthorizationService
    {
        private string _issuer;
        private string _stsDiscoveryEndpoint;
        private string _audience;
        private ICollection<SecurityKey> _signingKeys = null;
        public AuthorizationService(string stsDiscoveryEndpoint, string issuer, string audience)
        {
            if (string.IsNullOrEmpty(stsDiscoveryEndpoint) || string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(audience))
                throw new ArgumentNullException("stsDiscoveryEndpoint and issuer are required but null or empty");

            this._issuer = issuer;
            this._stsDiscoveryEndpoint = stsDiscoveryEndpoint;
            this._audience = audience;
        }
        public async Task<AuthorizationOutput> ValidateAsync(AuthenticationHeaderValue authHeader, string stsDiscoveryEndpoint, string issuer, string audience)
        {
            if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(stsDiscoveryEndpoint) || string.IsNullOrEmpty(audience))
                throw new ArgumentNullException("stsDiscoveryEndpoint, issuer & audience are required but null or empty");

            this._audience = audience;
            this._issuer = issuer;
            this._stsDiscoveryEndpoint = stsDiscoveryEndpoint;

            return await this.ValidateAsync(authHeader);
        }
        public async Task<AuthorizationOutput> ValidateAsync(AuthenticationHeaderValue authHeader)
        {
            if (string.IsNullOrEmpty(this._stsDiscoveryEndpoint) || string.IsNullOrEmpty(this._issuer) || string.IsNullOrEmpty(this._audience))
                throw new ArgumentNullException("stsDiscoveryEndpoint and issuer are required but null or empty");

            if (authHeader == null)
                throw new ArgumentNullException($"Parameter {nameof(AuthenticationHeaderValue)} is null. One possible issue could be a missing Auth-Header.");

            if (string.IsNullOrEmpty(authHeader.Parameter))
                throw new SecurityTokenValidationException("JWT Token is invalid. A valid JWT Token looks like following: Bearer eyJ0eXAiOiJKV1QiLCJ...");

            // Get the jwt bearer token from the authorization header 
            string jwtToken = authHeader.Parameter;

            //Retrieve informations from oidc discovery endpoint
            try
            {
                var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(this._stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());

                var config = await configManager.GetConfigurationAsync(CancellationToken.None);

                _issuer = $"{_issuer}, {config.Issuer}";
                _signingKeys = config.SigningKeys;
            }
            catch (Exception e)
            {
                throw e;
            }

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            //Validate token

            try
            {

                TokenValidationParameters validationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidAudiences = this._audience.Contains(",") ? this._audience.Split(',') : new string[] { this._audience },

                    ValidateIssuer = true,
                    ValidIssuers = _issuer.Contains(",") ? _issuer.Split(',') : new string[] { _issuer },

                    IssuerSigningKeys = _signingKeys,

                    ValidateIssuerSigningKey = true,

                    ValidateLifetime = true
                };

                SecurityToken validatedToken = new JwtSecurityToken();
                ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(jwtToken, validationParameters, out validatedToken);

                return new AuthorizationOutput()
                {
                    Audience = claimsPrincipal.FindFirst("aud")?.Value,
                    Type = (AuhtorizationType)Enum.Parse(typeof(AuhtorizationType), claimsPrincipal.FindFirst("typ").Value),
                    AuthorizedParty = claimsPrincipal.FindFirst("azp")?.Value,
                    Email = claimsPrincipal.FindFirst("email")?.Value,
                    FamilyName = claimsPrincipal.FindFirst("family_name")?.Value,
                    GivenName = claimsPrincipal.FindFirst("given_name")?.Value,
                    Issuer = claimsPrincipal.FindFirst("iss")?.Value,
                    ResourceAccess = JsonConvert.DeserializeObject<IDictionary<string, IDictionary<string, List<string>>>>(claimsPrincipal.FindFirst("resource_access")?.Value)
                };
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        public void CheckAuthenticationHeader(HttpRequest req)
        {
            if (req == null)
                throw new ArgumentNullException("HttpRequest req", "Parameter is null");
            if (!this.IsAuthentaticationHeaderProvided(req))
                throw new UnauthorizedAccessException("Authorization Header is required but null or empty");
        }
        public bool IsAuthentaticationHeaderProvided(HttpRequest req)
            => !string.IsNullOrEmpty(req?.Headers[HeaderNames.Authorization]);
    }
}
