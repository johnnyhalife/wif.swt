// <copyright file="SwtSecurityKeyClause.cs" company="open-source" >
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
    using System.IdentityModel.Tokens;

    /// <summary>
    /// The <see cref="SwtSecurityTokenHandler"/> passes an instance of this clause to 
    /// the <see cref="SwtIssuerTokenResolver"/> so that it knows it's an SWT that has 
    /// already been verified against the <see cref="SwtIssuerNameRegistry"/> trusted 
    /// issuers list. 
    /// </summary>
    /// <remarks>
    /// Because we only support one symmetric <see cref="SecurityKey"/> 
    /// for SWT, we don't need to differentiate between issuers.
    /// </remarks>
    public class SwtSecurityKeyClause : SecurityKeyIdentifierClause
    {
        public SwtSecurityKeyClause() : base("SWT")
        {
        }
    }
}
