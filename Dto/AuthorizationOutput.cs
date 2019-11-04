using System.Collections.Generic;

namespace DigitArc.Lib.Security.JwtTokenValidator.Dto
{
    public enum AuhtorizationType
    {
        Bearer
    }

    //This model is specific to your JWT Token parameters
    public class AuthorizationOutput
    {
        public string GivenName { get; set; }
        public string FamilyName { get; set; }
        public string Email { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public AuhtorizationType? Type { get; set; }
        public string AuthorizedParty { get; set; }
        public IDictionary<string, IDictionary<string, List<string>>> ResourceAccess { get; set; }
    }

}
