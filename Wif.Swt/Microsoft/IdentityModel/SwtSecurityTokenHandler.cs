// <copyright file="SwtSecurityTokenHandler.cs" company="open-source" >
//  Original (c) http://zamd.net/2011/02/08/using-simple-web-token-swt-with-wif/
//  Copyright (adapted version by kzu) NetFx (c) 2011 
//  Copyright binary (c) 2011  by Johnny Halife, Juan Pablo Garcia, Mauro Krikorian, Mariano Converti,
//                                Damian Martinez, Nico Bello, and Ezequiel Morito
//   
//  Redistribution and use in source and binary forms, with or without modification, are permitted.
//
//  The names of its contributors may not be used to endorse or promote products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// </copyright>

namespace Microsoft.IdentityModel.Swt
{
    using System;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Cryptography;
    using System.ServiceModel.Security;
    using System.ServiceModel.Web;
    using System.Text;
    using System.Web;
    using System.Xml;

    using Microsoft.IdentityModel.Claims;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// Handles SWT tokens.
    /// </summary>
    public class SwtSecurityTokenHandler : SecurityTokenHandler
    {
        public override Type TokenType
        {
            get { return typeof(SimpleWebToken); }
        }

        public override bool CanValidateToken
        {
            get { return true; }
        }

        public override bool CanWriteToken
        {
            get { return true; }
        }

        public override string[] GetTokenTypeIdentifiers()
        {
            return new[] { "http://schemas.microsoft.com/ws/2010/07/identitymodel/tokens/SWT" };
        }

        public override bool CanReadToken(XmlReader reader)
        {
            return
                reader.IsStartElement(WSSecurity10Constants.Elements.BinarySecurityToken, WSSecurity10Constants.Namespace) &&
                reader.GetAttribute(WSSecurity10Constants.Attributes.ValueType) == "http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0";
        }

        public override SecurityToken ReadToken(XmlReader reader)
        {
            if (!this.CanReadToken(reader))
                throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);

            var swtBuffer = Convert.FromBase64String(reader.ReadElementContentAsString());
            var swt = Encoding.Default.GetString(swtBuffer);

            try
            {
                return new SimpleWebToken(swt);
            }
            catch (InvalidSecurityTokenException)
            {
                throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);
            }
        }

        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            var swt = token as SimpleWebToken;

            if (swt == null)
                throw new InvalidSecurityTokenException();

            // Wrap the token into a binary token for XML transport.
            writer.WriteStartElement(WSSecurity10Constants.Elements.BinarySecurityToken, WSSecurity10Constants.Namespace);
            writer.WriteAttributeString(WSSecurity10Constants.Attributes.ValueType, "http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0");
            writer.WriteAttributeString(WSSecurity10Constants.Attributes.EncodingType, WSSecurity10Constants.EncodingTypes.Base64);
            writer.WriteValue(Convert.ToBase64String(Encoding.Default.GetBytes(swt.RawToken)));
            writer.WriteEndElement();
        }

        public override ClaimsIdentityCollection ValidateToken(SecurityToken token)
        {
            var swt = token as SimpleWebToken;
            if (swt == null)
                throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);

            if (this.Configuration.IssuerNameRegistry != null)
            {
                var resolvedIssuer = this.Configuration.IssuerNameRegistry.GetIssuerName(token);
                if (resolvedIssuer != swt.Issuer)
                    throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);
            }

            // If we get this far, it's because the issuer is a trusted one, or we don't 
            // care as we didn't setup an issuerNameRegistry at all. To the resolver 
            // always returns the key.
            var securityKey = this.Configuration.IssuerTokenResolver.ResolveSecurityKey(
                new SwtSecurityKeyClause()) as InMemorySymmetricSecurityKey;

            if (securityKey == null)
                throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);

            if (!IsHMACValid(swt.RawToken, securityKey.GetSymmetricKey()))
                throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);

            if (swt.IsExpired)
                throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);

            if (this.Configuration.AudienceRestriction.AudienceMode != System.IdentityModel.Selectors.AudienceUriMode.Never)
            {
                var allowedAudiences = this.Configuration.AudienceRestriction.AllowedAudienceUris;
                var swtAudienceUri = default(Uri);
                if (!Uri.TryCreate(swt.Audience, UriKind.RelativeOrAbsolute, out swtAudienceUri))
                    throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);

                if (!allowedAudiences.Any(uri => uri == swtAudienceUri))
                    throw new WebFaultException(System.Net.HttpStatusCode.Unauthorized);
            }

            var incomingIdentity = swt.ToClaimsIdentity();

            if (this.Configuration.SaveBootstrapTokens)
            {
                incomingIdentity.BootstrapToken = token;
            }

            return new ClaimsIdentityCollection(new IClaimsIdentity[] { incomingIdentity });
        }

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            var sb = new StringBuilder();

            foreach (var c in tokenDescriptor.Subject.Claims)
                sb.AppendFormat("{0}={1}&", HttpUtility.UrlEncode(c.ClaimType), HttpUtility.UrlEncode(c.Value));

            sb.AppendFormat("Issuer={0}&", HttpUtility.UrlEncode(tokenDescriptor.TokenIssuerName));
            sb.AppendFormat("Audience={0}&", HttpUtility.UrlEncode(tokenDescriptor.AppliesToAddress));

            var seconds = tokenDescriptor.Lifetime.Expires - tokenDescriptor.Lifetime.Created;
            double lifeTimeInSeconds = 3600;
            if (seconds.HasValue)
                lifeTimeInSeconds = seconds.Value.TotalSeconds;

            sb.AppendFormat("ExpiresOn={0:0}", DateTime.UtcNow.ToEpochTime() + lifeTimeInSeconds);

            var unsignedToken = sb.ToString();

            var key = (InMemorySymmetricSecurityKey)tokenDescriptor.SigningCredentials.SigningKey;
            var hmac = new HMACSHA256(key.GetSymmetricKey());
            var sig = hmac.ComputeHash(Encoding.ASCII.GetBytes(unsignedToken));

            var signedToken = string.Format("{0}&HMACSHA256={1}", unsignedToken, HttpUtility.UrlEncode(Convert.ToBase64String(sig)));

            return new SimpleWebToken(signedToken);
        }

        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            var swt = token as SimpleWebToken;
            if (swt == null)
                throw new InvalidSecurityTokenException("Expected SWT token.");

            return new KeyNameIdentifierClause(swt.Issuer);
        }

        private static bool IsHMACValid(string swt, byte[] sha256HMACKey)
        {
            var swtWithSignature = swt.Split(new string[] { string.Format("&{0}=", SwtConstants.HmacSha256) }, StringSplitOptions.None);
            if (swtWithSignature.Length != 2)
                return false;

            using (var hmac = new HMACSHA256(sha256HMACKey))
            {
                var locallyGeneratedSignatureInBytes = hmac.ComputeHash(Encoding.ASCII.GetBytes(swtWithSignature[0]));
                var locallyGeneratedSignature = HttpUtility.UrlEncode(Convert.ToBase64String(locallyGeneratedSignatureInBytes));

                return string.Equals(locallyGeneratedSignature, swtWithSignature[1], StringComparison.InvariantCulture);
            }
        }
    }
}
#pragma warning restore 0436