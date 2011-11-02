// <copyright file="Guard.cs" company="open-source" >
//  Copyright (adapted version by kzu) NetFx (c) 2011 
//
//  The names of its contributors may not be used to endorse or promote products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// </copyright>

using System;
using System.Diagnostics;
using System.Linq.Expressions;

/// <summary>
/// Common guard class for argument validation.
/// </summary>
[DebuggerStepThrough]
internal static class Guard
{
    /// <summary>
    /// Ensures the given <paramref name="value"/> is not null.
    /// Throws <see cref="ArgumentNullException"/> otherwise.
    /// </summary>
    public static void NotNull<T>(Expression<Func<T>> reference, T value)
    {
        if (value == null)
            throw new ArgumentNullException(GetParameterName(reference), "Parameter cannot be null.");
    }

    /// <summary>
    /// Ensures the given string <paramref name="value"/> is not null or empty.
    /// Throws <see cref="ArgumentNullException"/> in the first case, or 
    /// <see cref="ArgumentException"/> in the latter.
    /// </summary>
    public static void NotNullOrEmpty(Expression<Func<string>> reference, string value)
    {
        NotNull<string>(reference, value);
        if (value.Length == 0)
            throw new ArgumentException(GetParameterName(reference), "Parameter cannot be empty.");
    }

    private static string GetParameterName(Expression reference)
    {
        var lambda = reference as LambdaExpression;
        var member = lambda.Body as MemberExpression;

        return member.Member.Name;
    }
}