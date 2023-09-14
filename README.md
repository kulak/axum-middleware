# README

Various axum middleware.

## Inactivitiy Middleware

Shuts down axum based application if there are no incoming requests for set period of time.

## Examples

Examples directory provides sample applications utilizing the middleware.

## JWT Authutentication Delegate Middleware

JWT authentication middleware sends request to authentication URL with JWT extracted from the original request.  If response status is 200, then user is authenticated. Any other response status is treated as user is not authenticated.

This follows authentication model described in Nginx [ngx_http_auth_jwt_module](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html).  

An example implementation of authentication service conforming to the authentication model is [vouch-proxy](https://github.com/vouch/vouch-proxy).

User ID for authenticated user is extracted from JWT "sub" field and passed within request processing pipeline as AXUM extension.