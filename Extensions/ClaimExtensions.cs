using System;
using System.Security.Claims;

namespace DigitArc.Lib.Security.JwtTokenValidator.Extensions
{
    public static class ClaimExtensions
    {
        public static void UpdateClaim(this ClaimsIdentity claimsIdentity, Claim claim)
        {
            if (claim == null)
                throw new ArgumentNullException();

            Claim updateClaim = claimsIdentity.FindFirst(claim.Type);

            if (updateClaim == null)
                throw new NullReferenceException();

            claimsIdentity.RemoveClaim(updateClaim);
            claimsIdentity.AddClaim(claim);
        }
    }
}
