using DigitArc.Lib.Security.JwtTokenValidator.Dto;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace DigitArc.Lib.Security.JwtTokenValidator
{
    public interface IAuthorizationService
    {
        Task<AuthorizationOutput> ValidateAsync(AuthenticationHeaderValue authHeader);
        Task<AuthorizationOutput> ValidateAsync(AuthenticationHeaderValue authHeader, string stsDiscoveryEndpoint, string issuer, string audience);
    }
}
