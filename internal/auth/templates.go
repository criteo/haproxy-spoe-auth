package auth

// RedirectPage is a template used for the final redirection
var RedirectPageTemplate = `
<head>
<title>Redirection in progress</title>
  <meta http-equiv="refresh" content="0; URL={{.URL}}" />
</head>
<body>
</body>`

// ErrorPage is a template used in the case the final redirection cannot happen due to the bad signature of the original URL
var ErrorPageTemplate = `
<head>
  <title>Error on redirection</title>
</head>
<body>
You cannot be redirected to this untrusted url {{.URL}}.
</body>`

// LogoutPage is an HTML content stating the user has been logged out successfully
var LogoutPageTemplate = `
<head>
<title>Logout</title>
</head>
<body>
You have been logged out successfully.
</body>`
