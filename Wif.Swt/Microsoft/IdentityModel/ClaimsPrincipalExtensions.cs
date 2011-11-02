// <copyright file="ClaimsPrincipalExtensions.cs" company="open-source" >
//  Copyright binary (c) 2011  by Johnny Halife, Juan Pablo Garcia, Mauro Krikorian, Mariano Converti,
//                                Damian Martinez, Nico Bello, and Ezequiel Morito
//   
//  Redistribution and use in source and binary forms, with or without modification, are permitted.
//
//  The names of its contributors may not be used to endorse or promote products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// </copyright>

namespace Microsoft.IdentityModel
{
    using System.Security.Principal;
    using Microsoft.IdentityModel.Claims;

    /// <summary>
    /// Extensions to simplify the IPrincipal management.
    /// </summary>
    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Retrieves the Bootstrap token from the IClaimsPrincipal (this) if given principal
        /// has it.
        /// </summary>
        /// <param name="principal">Extended principal.</param>
        /// <returns>Bootstrap Token</returns>
        public static string BootstrapToken(this IPrincipal principal)
        {
            IClaimsPrincipal claimsPrincipal = principal as IClaimsPrincipal;

            if (claimsPrincipal != null)
            {
                IClaimsIdentity claimsIdentity = (IClaimsIdentity)claimsPrincipal.Identity;
                return claimsIdentity.BootstrapToken.ToString();
            }

            return null;
        }
    }
}