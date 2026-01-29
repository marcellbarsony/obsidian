---
id: Error Pages
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Error-Pages
links: "[[Webapp]]"
---

# Error Page

Error messages can leak information regarding the technologies used

<!-- Get Error Page {{{-->
## Get Error Page

Retrieve the error page (*status code `404`*)

```sh
curl -X GET http://$target/404page
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> curl -X GET http://example.com/404page
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Error Pages {{{-->
## Error Pages

Default error page examples

<!-- Resources {{{-->
> [!info]- Resources
>
> [0xdf - 404 Cheatsheet](https://0xdf.gitlab.io/cheatsheets/404#)
<!-- }}} -->

<!-- AIOHTTP {{{-->
### AIOHTTP

[AIOHTTP](https://docs.aiohttp.org/en/stable/) is a
"Asynchronous HTTP Client/Server for asyncio and Python"

![[404-aiohttp.png]]

<!-- Example {{{-->
> [!example]-
>
> There’s no HTML, just the plaintext.
> It is generated from the `web_exceptions.py` file
> that defines the various exceptions, including `HTTPNotFound`
>
> ```sh
> class HTTPNotFound(HTTPClientError):
>     status_code = 404
> ```
>
> The `HTTPClientError` class defines the `text` as
>
> ```sh
>    if text is None:
>        if not self.empty_body:
>             text = f"{self.status_code}: {reason}"
> ```
>
> `status_code` is set at the bottom of the file,
> pulling from the `http` module
>
> ```sh
> def _initialize_default_reason() -> None:
>     for obj in globals().values():
>         if isinstance(obj, type) and issubclass(obj, HTTPException):
>             if obj.status_code >= 0:
>                 try:
>                     status = HTTPStatus(obj.status_code)
>                     obj.default_reason = status.phrase
>                 except ValueError:
>                     pass
>
>
> _initialize_default_reason()
> del _initialize_default_reason
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Apache httpd {{{-->
### Apache httpd

[[Apache HTTP Server/General|Apache httpd]]
web server (*similar to [[#Nginx]] that it*) is used
to serve static pages or to route requests through
to the desired backup application

![[404-apache.png]]

If the server is configured with `ServerSignature Off`,
then Apache version and OS won't show up

<!-- Example {{{-->
> [!example]-
>
> ```sh
> <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
> <html><head>
> <title>404 Not Found</title>
> </head><body>
> <h1>Not Found</h1>
> <p>The requested URL was not found on this server.</p>
> <hr>
> <address>Apache/2.4.41 (Ubuntu) Server at 10.10.11.136 Port 80</address>
> </body></html>
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Apache Tomcat {{{-->
### Apache Tomcat

[[Apache Tomcat/General|Apache Tomcat]]
is a web framework built in Java that use technology like
Java Server Pages (*JSP*), Servlets,
and Web Application Archives (*WAR*)

![[404-tomcat.png]]

<!-- Example {{{-->
> [!example]-
>
> The HTML is one line
>
> ```sh
> <!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404 – Not Found</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Message</b> &#47;doesnotexist</p><p><b>Description</b> The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p><hr class="line" /><h3>Apache Tomcat/9.0.31 (Ubuntu)</h3></body></html>
> ```
>
> The error text is set on [GitHub](https://github.com/apache/tomcat/blob/main/java/org/apache/catalina/valves/LocalStrings.properties#L68-L69)
>
> ```sh
> http.404.desc=The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.
> http.404.reason=Not Found
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- ASP.NET Core {{{-->
### ASP.NET Core

[ASP.NET Core](https://dotnet.microsoft.com/en-us/apps/aspnet)
is a cross-platform web framework build on .NET,
though it’s typically seen on Windows hosts

ASP.NET applications
are typically hosted behind a webserver like [[#IIS]],
so `/doesnotexist` may result in the [[#IIS|IIS 404]],
where as `/doesnotexist.aspx` could be routed through
to ASP.NET where it returns the ASP.NET 404 page

![[404-asp-dotnet.png]]

<!-- Example {{{-->
> [!example]-
>
> Raw HTML
>
> ```sh
> <!DOCTYPE html>
> <html>
>     <head>
>         <title>The resource cannot be found.</title>
>         <meta name="viewport" content="width=device-width" />
>         <style>
>          body {font-family:"Verdana";font-weight:normal;font-size: .7em;color:black;} 
>          p {font-family:"Verdana";font-weight:normal;color:black;margin-top: -5px}
>          b {font-family:"Verdana";font-weight:bold;color:black;margin-top: -5px}
>          H1 { font-family:"Verdana";font-weight:normal;font-size:18pt;color:red }
>          H2 { font-family:"Verdana";font-weight:normal;font-size:14pt;color:maroon }
>          pre {font-family:"Consolas","Lucida Console",Monospace;font-size:11pt;margin:0;padding:0.5em;line-height:14pt}
>          .marker {font-weight: bold; color: black;text-decoration: none;}
>          .version {color: gray;}
>          .error {margin-bottom: 10px;}
>          .expandable { text-decoration:underline; font-weight:bold; color:navy; cursor:hand; }
>          @media screen and (max-width: 639px) {
>           pre { width: 440px; overflow: auto; white-space: pre-wrap; word-wrap: break-word; }
>          }
>          @media screen and (max-width: 479px) {
>           pre { width: 280px; }
>          }
>         </style>
>     </head>
>
>     <body bgcolor="white">
>
>             <span><H1>Server Error in '/' Application.<hr width=100% size=1 color=silver></H1>
>
>             <h2> <i>The resource cannot be found.</i> </h2></span>
>
>             <font face="Arial, Helvetica, Geneva, SunSans-Regular, sans-serif ">
>
>             <b> Description: </b>HTTP 404. The resource you are looking for (or one of its dependencies) could have been removed, had its name changed, or is temporarily unavailable. &nbsp;Please review the following URL and make sure that it is spelled correctly.
>             <br><br>
>
>             <b> Requested URL: </b>/default.aspx<br><br>
>
>     </body>
> </html>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Blazor {{{-->
### Blazor

The [Blazor](https://dotnet.microsoft.com/en-us/apps/aspnet/web-apps/blazor)
web framework is built into ASP.NET Core,
and is a .NET and C# frontend framework for building interactive web applications without JavaScript

![[404-blazor.png]]

<!-- }}} -->

<!-- Django {{{-->
### Django

[Django](https://www.djangoproject.com/)
is a [[Python/General|Python]] web framework

The 404 page is similar to [[#Apache]] and [[#Flask]]

![[404-django.png]]

<!-- Example {{{-->
> [!example]-
>
> ```sh
> <!doctype html>
> <html lang="en">
> <head>
>   <title>Not Found</title>
> </head>
> <body>
>   <h1>Not Found</h1><p>The requested resource was not found on this server.</p>
> </body>
> </html>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Express {{{-->
### Express

Express is a JavaScript NodeJS web framework

The 404 page is same as [[#Fiber]]

![[404-fiber.png]]

<!-- Example {{{-->
> [!example]-
>
> ```html
> <!DOCTYPE html>
> <html lang="en">
> <head>
> <meta charset="utf-8">
> <title>Error</title>
> </head>
> <body>
> <pre>Cannot GET /0xdf</pre>
> </body>
> </html>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- FastAPI {{{-->
### FastAPI

[FastAPI](https://fastapi.tiangolo.com/)
is [[Python/General|Python]] web framework
based on Python type hints

When a path is not found, it returns JSON

![[404-fastapi.png]]

<!-- Example {{{-->
> [!example]-
>
> ```json
> {"detail":"Not Found"}
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Fiber {{{-->
### Fiber

[Fiber](https://docs.gofiber.io/)
is a [[Go/General|Go]]-based web framework
where the default 404 page returns onluy a text string
including the search path

The 404 page is same as [[#Express]]

![[404-fiber.png]]

<!-- Example {{{-->
> [!example]-
>
> [Source](https://github.com/gofiber/fiber/blob/main/router.go#L138-L139)
>
> ```sh
>  // If c.Next() does not match, return 404
>     err := NewError(StatusNotFound, "Cannot "+c.Method()+" "+c.getPathOriginal())
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Flask {{{-->
### Flask

[Flask](https://flask.palletsprojects.com/en/stable/)
is a [[Python/General|Python]] web framework

![[404-flask.png]]

<!-- Example {{{-->
> [!example]-
>
>
> Source
>
> ```sh
> <!doctype html>
> <html lang=en>
> <title>404 Not Found</title>
> <h1>Not Found</h1>
> <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
> ```
>
> Generated by this exception
>
> ```sh
> class NotFound(HTTPException):
>     """*404* `Not Found`
>
>     Raise if a resource does not exist and never existed.
>     """
>
>     code = 404
>     description = (
>         "The requested URL was not found on the server. If you entered"
>         " the URL manually please check your spelling and try again."
>     )
> ```
>
> That exception is printed using the `get_body` function
> in that same file
>
> ```sh
>     def get_body(
>         self,
>         environ: WSGIEnvironment | None = None,
>         scope: dict[str, t.Any] | None = None,
>     ) -> str:
>         """Get the HTML body."""
>         return (
>             "<!doctype html>\n"
>             "<html lang=en>\n"
>             f"<title>{self.code} {escape(self.name)}</title>\n"
>             f"<h1>{escape(self.name)}</h1>\n"
>             f"{self.get_description(environ)}\n"
>         )
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Gin {{{-->
### Gin

[Gin](https://gin-gonic.com/)
is a [[Go/General|Go]]-based framework

![[404-gin.png]]

<!-- Example {{{-->
> [!example]-
>
> ```sh
> var (
>     default404Body = []byte("404 page not found")
>     default405Body = []byte("405 method not allowed")
> )
> ```
<!-- }}} -->

<!-- }}} -->

<!-- IIS {{{-->
### IIS

[[Microsoft IIS/General|IIS]] is Microsoft’s web server

![[404-iis.png]]

<!-- Example {{{-->
> [!example]-
>
> The raw HTML includes the CSS inline
>
> ```html
> <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
> <html xmlns="http://www.w3.org/1999/xhtml">
> <head>
> <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
> <title>404 - File or directory not found.</title>
> <style type="text/css">
> <!--
> body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
> fieldset{padding:0 15px 10px 15px;} 
> h1{font-size:2.4em;margin:0;color:#FFF;}
> h2{font-size:1.7em;margin:0;color:#CC0000;} 
> h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} 
> #header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
> background-color:#555555;}
> #content{margin:0 0 0 2%;position:relative;}
> .content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
> -->
> </style>
> </head>
> <body>
> <div id="header"><h1>Server Error</h1></div>
> <div id="content">
>  <div class="content-container"><fieldset>
>   <h2>404 - File or directory not found.</h2>
>   <h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>
>  </fieldset></div>
> </div>
> </body>
> </html>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Jetty {{{-->
### Jetty

[Jetty](https://jetty.org/index.html) is a Java web framework

![[404-jetty.png]]

<!-- Example {{{-->
> [!example]-
>
> ```sh
> <!DOCTYPE html>
> <html lang="en">
> <head>
> <title>Error 404 - Not Found</title>
> <meta charset="utf-8">
> <style>body { font-family: sans-serif; } table, td { border: 1px solid #333; } td, th { padding: 5px; } thead, tfoot { background-color: #333; color: #fff; } </style>
> </head>
> <body>
> <h2>Error 404 - Not Found.</h2>
> <p>No context on this server matched or handled this request.</p>
> <p>Contexts known to this server are:</p>
> <table class="contexts"><thead><tr><th>Context Path</th><th>Display Name</th><th>Status</th><th>LifeCycle</th></tr></thead><tbody>
> </tbody></table><hr/>
> <a href="https://jetty.org"><img alt="icon" src="/favicon.ico"/></a>&nbsp;<a href="https://jetty.org">Powered by Eclipse Jetty:// Server</a><hr/>
> </body>
> </html>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Laravel {{{-->
### Laravel

[Laravel](https://laravel.com/) is a PHP web framework

The 404 page is similar to [[#NextJS]]

![[404-laravel.png]]

<!-- Example {{{-->
> [!example]-
>
> ```sh
> <!DOCTYPE html>
> <html lang="en">
>     <head>
>         <meta charset="utf-8">
>         <meta name="viewport" content="width=device-width, initial-scale=1">
>
>         <title>Not Found</title>
>
>         <style>
>             /*! normalize.css v8.0.1 | MIT License | github.com/necolas/normalize.css */html{line-height:1.15;-webkit-text-size-adjust:100%}body{margin:0}a{background-color:transparent}code{font-family:monospace,monospace;font-size:1em}[hidden]{display:none}html{font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;line-height:1.5}*,:after,:before{box-sizing:border-box;border:0 solid #e2e8f0}a{color:inherit;text-decoration:inherit}code{font-family:Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace}svg,video{display:block;vertical-align:middle}video{max-width:100%;height:auto}.bg-white{--bg-opacity:1;background-color:#fff;background-color:rgba(255,255,255,var(--bg-opacity))}.bg-gray-100{--bg-opacity:1;background-color:#f7fafc;background-color:rgba(247,250,252,var(--bg-opacity))}.border-gray-200{--border-opacity:1;border-color:#edf2f7;border-color:rgba(237,242,247,var(--border-opacity))}.border-gray-400{--border-opacity:1;border-color:#cbd5e0;border-color:rgba(203,213,224,var(--border-opacity))}.border-t{border-top-width:1px}.border-r{border-right-width:1px}.flex{display:flex}.grid{display:grid}.hidden{display:none}.items-center{align-items:center}.justify-center{justify-content:center}.font-semibold{font-weight:600}.h-5{height:1.25rem}.h-8{height:2rem}.h-16{height:4rem}.text-sm{font-size:.875rem}.text-lg{font-size:1.125rem}.leading-7{line-height:1.75rem}.mx-auto{margin-left:auto;margin-right:auto}.ml-1{margin-left:.25rem}.mt-2{margin-top:.5rem}.mr-2{margin-right:.5rem}.ml-2{margin-left:.5rem}.mt-4{margin-top:1rem}.ml-4{margin-left:1rem}.mt-8{margin-top:2rem}.ml-12{margin-left:3rem}.-mt-px{margin-top:-1px}.max-w-xl{max-width:36rem}.max-w-6xl{max-width:72rem}.min-h-screen{min-height:100vh}.overflow-hidden{overflow:hidden}.p-6{padding:1.5rem}.py-4{padding-top:1rem;padding-bottom:1rem}.px-4{padding-left:1rem;padding-right:1rem}.px-6{padding-left:1.5rem;padding-right:1.5rem}.pt-8{padding-top:2rem}.fixed{position:fixed}.relative{position:relative}.top-0{top:0}.right-0{right:0}.shadow{box-shadow:0 1px 3px 0 rgba(0,0,0,.1),0 1px 2px 0 rgba(0,0,0,.06)}.text-center{text-align:center}.text-gray-200{--text-opacity:1;color:#edf2f7;color:rgba(237,242,247,var(--text-opacity))}.text-gray-300{--text-opacity:1;color:#e2e8f0;color:rgba(226,232,240,var(--text-opacity))}.text-gray-400{--text-opacity:1;color:#cbd5e0;color:rgba(203,213,224,var(--text-opacity))}.text-gray-500{--text-opacity:1;color:#a0aec0;color:rgba(160,174,192,var(--text-opacity))}.text-gray-600{--text-opacity:1;color:#718096;color:rgba(113,128,150,var(--text-opacity))}.text-gray-700{--text-opacity:1;color:#4a5568;color:rgba(74,85,104,var(--text-opacity))}.text-gray-900{--text-opacity:1;color:#1a202c;color:rgba(26,32,44,var(--text-opacity))}.uppercase{text-transform:uppercase}.underline{text-decoration:underline}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.tracking-wider{letter-spacing:.05em}.w-5{width:1.25rem}.w-8{width:2rem}.w-auto{width:auto}.grid-cols-1{grid-template-columns:repeat(1,minmax(0,1fr))}@-webkit-keyframes spin{0%{transform:rotate(0deg)}to{transform:rotate(1turn)}}@keyframes spin{0%{transform:rotate(0deg)}to{transform:rotate(1turn)}}@-webkit-keyframes ping{0%{transform:scale(1);opacity:1}75%,to{transform:scale(2);opacity:0}}@keyframes ping{0%{transform:scale(1);opacity:1}75%,to{transform:scale(2);opacity:0}}@-webkit-keyframes pulse{0%,to{opacity:1}50%{opacity:.5}}@keyframes pulse{0%,to{opacity:1}50%{opacity:.5}}@-webkit-keyframes bounce{0%,to{transform:translateY(-25%);-webkit-animation-timing-function:cubic-bezier(.8,0,1,1);animation-timing-function:cubic-bezier(.8,0,1,1)}50%{transform:translateY(0);-webkit-animation-timing-function:cubic-bezier(0,0,.2,1);animation-timing-function:cubic-bezier(0,0,.2,1)}}@keyframes bounce{0%,to{transform:translateY(-25%);-webkit-animation-timing-function:cubic-bezier(.8,0,1,1);animation-timing-function:cubic-bezier(.8,0,1,1)}50%{transform:translateY(0);-webkit-animation-timing-function:cubic-bezier(0,0,.2,1);animation-timing-function:cubic-bezier(0,0,.2,1)}}@media (min-width:640px){.sm\:rounded-lg{border-radius:.5rem}.sm\:block{display:block}.sm\:items-center{align-items:center}.sm\:justify-start{justify-content:flex-start}.sm\:justify-between{justify-content:space-between}.sm\:h-20{height:5rem}.sm\:ml-0{margin-left:0}.sm\:px-6{padding-left:1.5rem;padding-right:1.5rem}.sm\:pt-0{padding-top:0}.sm\:text-left{text-align:left}.sm\:text-right{text-align:right}}@media (min-width:768px){.md\:border-t-0{border-top-width:0}.md\:border-l{border-left-width:1px}.md\:grid-cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}}@media (min-width:1024px){.lg\:px-8{padding-left:2rem;padding-right:2rem}}@media (prefers-color-scheme:dark){.dark\:bg-gray-800{--bg-opacity:1;background-color:#2d3748;background-color:rgba(45,55,72,var(--bg-opacity))}.dark\:bg-gray-900{--bg-opacity:1;background-color:#1a202c;background-color:rgba(26,32,44,var(--bg-opacity))}.dark\:border-gray-700{--border-opacity:1;border-color:#4a5568;border-color:rgba(74,85,104,var(--border-opacity))}.dark\:text-white{--text-opacity:1;color:#fff;color:rgba(255,255,255,var(--text-opacity))}.dark\:text-gray-400{--text-opacity:1;color:#cbd5e0;color:rgba(203,213,224,var(--text-opacity))}}
>         </style>
>
>         <style>
>             body {
>                 font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
>             }
>         </style>
>     </head>
>     <body class="antialiased">
>         <div class="relative flex items-top justify-center min-h-screen bg-gray-100 dark:bg-gray-900 sm:items-center sm:pt-0">
>             <div class="max-w-xl mx-auto sm:px-6 lg:px-8">
>                 <div class="flex items-center pt-8 sm:justify-start sm:pt-0">
>                     <div class="px-4 text-lg text-gray-500 border-r border-gray-400 tracking-wider">
>                         404                    </div>
>
>                     <div class="ml-4 text-lg text-gray-500 uppercase tracking-wider">
>                         Not Found                    </div>
>                 </div>
>             </div>
>         </div>
>     </body>
> </html>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- NextJS {{{-->
### NextJS

[NextJS](https://nextjs.org/) is a framework
built on the [React framework](https://react.dev/) frontend
and [NodeJS](https://nodejs.org/en) on the backend

The 404 page is similar to [[#Laravel]]

![[404-nextjs.png]]

<!-- Example {{{-->
> [!example]-
>
> The HTML is on one line
>
> ```sh
> <!DOCTYPE html><html><head><style data-next-hide-fouc="true">body{display:none}</style><noscript data-next-hide-fouc="true"><style>body{display:block}</style></noscript><meta charSet="utf-8"/><meta name="viewport" content="width=device-width"/><title>404: This page could not be found</title><meta name="next-head-count" content="3"/><noscript data-n-css=""></noscript><script defer="" nomodule="" src="/_next/static/chunks/polyfills.js"></script><script src="/_next/static/chunks/webpack.js" defer=""></script><script src="/_next/static/chunks/main.js" defer=""></script><script src="/_next/static/chunks/pages/_app.js" defer=""></script><script src="/_next/static/chunks/pages/_error.js" defer=""></script><script src="/_next/static/development/_buildManifest.js" defer=""></script><script src="/_next/static/development/_ssgManifest.js" defer=""></script><noscript id="__next_css__DO_NOT_USE__"></noscript></head><body><div id="__next"><div style="font-family:system-ui,&quot;Segoe UI&quot;,Roboto,Helvetica,Arial,sans-serif,&quot;Apple Color Emoji&quot;,&quot;Segoe UI Emoji&quot;;height:100vh;text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:center"><div style="line-height:48px"><style>body{color:#000;background:#fff;margin:0}.next-error-h1{border-right:1px solid rgba(0,0,0,.3)}@media (prefers-color-scheme:dark){body{color:#fff;background:#000}.next-error-h1{border-right:1px solid rgba(255,255,255,.3)}}</style><h1 class="next-error-h1" style="display:inline-block;margin:0 20px 0 0;padding-right:23px;font-size:24px;font-weight:500;vertical-align:top">404</h1><div style="display:inline-block"><h2 style="font-size:14px;font-weight:400;line-height:28px">This page could not be found<!-- -->.</h2></div></div></div></div><script src="/_next/static/chunks/react-refresh.js"></script><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"statusCode":404}},"page":"/_error","query":{},"buildId":"development","isFallback":false,"gip":true,"scriptLoader":[]}</script></body></html>
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Nginx {{{-->
### Nginx

[[Nginx/General|Nginx]]
is a reverse proxy / web server / load balancer application
that can be used to serve static pages,
or manage various applications running behind it

![[404-nginx.png]]

<!-- Example {{{-->
> [!example]-
>
> [Source](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_special_response.c#L132-L137)
>
> ```html
> <html>
> <head><title>404 Not Found</title></head>
> <body>
> <center><h1>404 Not Found</h1></center>
> <hr><center>nginx/1.24.0</center>
> </body>
> </html>
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- PHP-FPM {{{-->
### PHP-FPM

[PHP-FPM](https://php-fpm.org/) (*PHP FastCGI Process Manager*),
is the PHP implementation for taking requests from a webserver
like Apache or nginx
and managing processes to handle the PHP execution
of the requested URL / page

![[404-php-fpm.png]]

<!-- Example {{{-->
> [!example]-
>
> [Source](https://github.com/php/php-src/blob/master/sapi/fpm/fpm/fpm_main.c#L1887-L1895)
>
> ```sh
>    zend_try {
>        zlog(ZLOG_DEBUG, "Primary script unknown");
>        SG(sapi_headers).http_response_code = 404;
>        PUTS("File not found.\n");
>    } zend_catch {
>    } zend_end_try();
>    goto fastcgi_request_done;
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Ruby on Rails {{{-->
### Ruby on Rails

[Ruby on Rails](https://rubyonrails.org/) is a Ruby web framework

![[404-ruby.png]]

<!-- Example {{{-->
> [!example]-
>
> The HTML is long as it includes CSS information
>
> ```sh
> <!DOCTYPE html>
> <html>
> <head>
>   <title>The page you were looking for doesn't exist (404)</title>
>   <meta name="viewport" content="width=device-width,initial-scale=1">
>   <style>
>   .rails-default-error-page {
>     background-color: #EFEFEF;
>     color: #2E2F30;
>     text-align: center;
>     font-family: arial, sans-serif;
>     margin: 0;
>   }
>
>   .rails-default-error-page div.dialog {
>     width: 95%;
>     max-width: 33em;
>     margin: 4em auto 0;
>   }
>
> ...
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Spring Boot {{{-->
### Spring Boot

[Spring Boot]() is a Java web framework
for creating Spring-based web applications

![[404-spring-boot.png]]

<!-- Example {{{-->
> [!example]-
>
> The raw HTML is one line (shown here wrapped):
>
> ```sh
> <html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p><div id='created'>Wed Sep 25 12:55:53 UTC 2024</div><div>There was an unexpected error (type=Not Found, status=404).</div><div></div></body></html>
> ```
>
> The source the generates this is in `ErrorMvcAutoConfiguration.java`
> on [GitHub](https://github.com/spring-projects/spring-boot)
>
> ```sh
>     builder.append("<html><body><h1>Whitelabel Error Page</h1>")
>         .append("<p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>")
>         .append("<div id='created'>")
>         .append(timestamp)
>         .append("</div>")
>         .append("<div>There was an unexpected error (type=")
>         .append(htmlEscape(model.get("error")))
>         .append(", status=")
>         .append(htmlEscape(model.get("status")))
>         .append(").</div>");
>     if (message != null) {
>         builder.append("<div>").append(htmlEscape(message)).append("</div>");
>     }
>     if (trace != null) {
>         builder.append("<div style='white-space:pre-wrap;'>").append(htmlEscape(trace)).append("</div>");
>     }
>     builder.append("</body></html>");
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Symfony {{{-->
### Symfony

[Symfony](https://symfony.com/) is a PHP framework

![[404-symfony.png]]

<!-- Example {{{-->
> [!example]-
>
> ```sh
> <!DOCTYPE html>
> <html lang="en">
> <head>
>     <meta charset="UTF-8" />
>     <meta name="robots" content="noindex,nofollow,noarchive" />
>     <title>An Error Occurred: Not Found</title>
>     <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 128 128%22><text y=%221.2em%22 font-size=%2296%22>❌</text></svg>" />
>     <style>body { background-color: #fff; color: #222; font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; }
> .container { margin: 30px; max-width: 600px; }
> h1 { color: #dc3545; font-size: 24px; }
> h2 { font-size: 18px; }</style>
> </head>
> <body>
> <div class="container">
>     <h1>Oops! An Error Occurred</h1>
>     <h2>The server returned a "404 Not Found".</h2>
>
>     <p>
>         Something is broken. Please let us know what you were doing when this error occurred.
>         We will fix it as soon as possible. Sorry for any inconvenience caused.
>     </p>
> </div>
> </body>
> </html>
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
