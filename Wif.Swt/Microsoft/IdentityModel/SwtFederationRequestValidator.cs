// <copyright file="SwtFederationRequestValidator.cs" company="open-source" >
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
    using System.Linq;
    using System.Text;
    using System.Web;
    using System.Web.Util;
    using System.Xml;
    using System.Xml.Linq;
    using IdentityModel.Protocols.WSFederation;

    /// <summary>
    /// This SwtFederationRequestValidator validates the wresult parameter of 
    /// the WS-Federation passive protocol by checking for a SimpleWebToken on Result 
    /// parameter. The validity of the message contents are verified later by the SwtSecurityTokenHandler.
    /// </summary>
    public class SwtFederationRequestValidator : RequestValidator
    {
        protected override bool IsValidRequestString(HttpContext context, string value, RequestValidationSource requestValidationSource, string collectionKey, out int validationFailureIndex)
        {
            validationFailureIndex = 0;

            if (requestValidationSource == RequestValidationSource.Form && collectionKey.Equals(WSFederationConstants.Parameters.Result, StringComparison.Ordinal))
            {
                XNamespace aw = "http://schemas.xmlsoap.org/ws/2005/02/trust";

                using (var xtr = new XmlTextReader(value, XmlNodeType.Element, null))
                {
                    var root = XElement.Load(xtr);
                    var requestedToken = root.Elements(aw + "RequestedSecurityToken");

                    if (!requestedToken.Any())
                        return false;

                    var encodedDataAsBytes = Convert.FromBase64String(requestedToken.First().Value);
                    var acsToken = Encoding.UTF8.GetString(encodedDataAsBytes, 0, encodedDataAsBytes.Length);

                    // We're assuming any other errors from the token parse will fire up as 
                    // exceptions
                    return new SimpleWebToken(acsToken) != null;
                }
            }

            return base.IsValidRequestString(context, value, requestValidationSource, collectionKey, out validationFailureIndex);
        }
    }
}