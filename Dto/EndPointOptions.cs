namespace DigitArc.Lib.Security.JwtTokenValidator.Dto
{
    public class EndPointOptions
    {
        public string Name { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string StsDiscoveryEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string TenantId { get; set; }
        public string Instance { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string CallbackPath { get; set; }
        public string ResponseType { get; set; }
        public AuthenticatorData AuthenticatorData { get; set; }

    }
    public class AuthenticatorData
    {
        public string Surname { get; set; }
        public string Givenname { get; set; }
        public string Email { get; set; }
        public string UserId { get; set; }
        public string Name { get; set; }
        public string TenantId { get; set; }
        public string ProviderId { get; set; }
    }
}
