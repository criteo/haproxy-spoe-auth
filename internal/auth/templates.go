package auth

// Names to refer error templates in Go template engine.
const (
	errNameRedirect   = "redirectError"
	errNameBadRequest = "badRequestError"
	errNameInternal   = "internalServerError"
)

// RedirectPage is a template used for the final redirection
var RedirectPageTemplate = `<html>
<head>
  <title>Redirection in progress</title>
  <meta http-equiv="refresh" content="0; URL={{.URL}}" />
</head>
<body>Redirection in progress...</body>
</html>`

// ErrorPage is a template used in the case the final redirection cannot happen due to the bad signature of the original URL
var RedirectErrorPageTemplate = `<html>
<head><title>Error on redirection</title></head>
<body>You cannot be redirected to this untrusted url {{.URL}}.</body>
</html>`

// LogoutPage is an HTML content stating the user has been logged out successfully
var LogoutPageTemplate = `<html>
<head><title>Logout</title></head>
<body>You have been logged out successfully.</body>
</html>`

var BadRequestTemplate = `<html>
  <head>
    <title>Bad request</title>
  </head>
  <body>
    <p>Bad request: your browser sent a a request we could not process.
    <p>Try to close this page and open it again.
    {{ if .SupportEmail }}
    <p>If the issue persists, please contact <a href="mailto:{{ .SupportEmail }}?subject={{ .SupportEmailSubject }}">Support Team</a>
    {{ end }}
  </body>
</html>`

var InternalServerErrorTemplate = `<html>
  <head>
    <title>Internal Server Error</title>
  </head>
  <body>
    <p>Internal Server Error: something is wrong at our side.
    <p>Try to reload this page in 5-10 seconds.
    {{ if .supportEmail }}
    <p>If the issue persists, please contact <a href="mailto:{{ .SupportEmail }}?subject={{ .SupportEmailSubject }}">Support Team</a>
    {{ end }}
  </body>
</html>`
