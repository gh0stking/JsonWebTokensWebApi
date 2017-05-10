using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;

namespace BioBankServer.FrameWork.Filter
{
    /// <summary>
    /// API 请求Token验证。
    /// </summary>
    public class ApiAuthHandler : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpResponseMessage errorResponse = null;

            try
            {
                IEnumerable<string> authHeaderValues;
                request.Headers.TryGetValues("Authorization", out authHeaderValues);

                if (authHeaderValues == null)
                    return base.SendAsync(request, cancellationToken);

                var bearerToken = authHeaderValues.ElementAt(0);
                var token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;
                var secret = ConfigurationManager.AppSettings["jwtKey"];
                var user = HttpContext.Current.User.Identity.GetUserId();
            }
            catch (Exception ex)
            {
                errorResponse = request.CreateErrorResponse(HttpStatusCode.Unauthorized, string.Format("Server Error:{0}", ex.Message));
            }

            return errorResponse != null ? Task.FromResult(errorResponse) : base.SendAsync(request, cancellationToken);
        }
    }
}