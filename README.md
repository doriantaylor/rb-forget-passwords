# LazyAuth - Web Authentication, but lazy

LazyAuth is a stand-alone Web authentication module that replicates
the "forgot-my-password" user flow, which will, on request, e-mail a
special link to an address on a predefined list, in lieu of
password-based authentication. This module makes use of [a
lesser-known feature of the FastCGI
protocol](https://fastcgi-archives.github.io/FastCGI_Specification.html#S6.3)
to do its work, and plugs into a receiving end such as [Apache's
`mod_authnz_fcgi`](https://httpd.apache.org/docs/2.4/mod/mod_authnz_fcgi.html).

## Rationale & Goal

I have various Web properties littered around the internet in various
stages of development. Sometimes I want to show these properties to
people, but only _certain_ people—an example being both existing and
prospective clients.

Providing meaningful protection to a website almost always entails
some kind of authentication mechanism, and unless you go exotic, this
almost always means some kind of password. A single, shared password
is often inadequate protection because it can be leaked. This means
everybody to whom I would want to access one of these Web properties
would need their own password.

In this particular case, I am looking to support a relatively small
number of people, the total extent of whom is not necessarily known up
front. Under a password-based authentication regime, not only would I
be burdening clients and prospects with yet another set of
authentication credentials to manage, but I would also be burdening
_myself_ with the chore of fielding requests for new accounts* as
stragglers trickle in, as well as reset or retrieve lost passwords.

> \* I suppose I could set up UI for _them_ to create their own
> accounts and retrieve their lost passwords, but that would actually
> be more work than the solution I propose here, and the net effect
> would be to _further_ burden my users.

The solution to this problem stems from observing that the long tail
of Web authentication is serviced by the archetypal **forgot my
password** flow _itself_, so why force people to go through the extra
step of _creating_, and then _remembering_, a password?

The goal, then, is to create an authentication module that replicates
the forgot-my-password flow, provides about the same security as
`Basic` authentication over SSL, has a generic-enough user interface
to be merged seamlessly into any existing system, and otherwise
interacts minimally with any downstream access control mechanism or
Web application, including static content. An additional requirement
is that a mapping scheme (e.g. website domain to e-mail domain) can be
set up to provision identities (accounts) automatically.

## How It Works

This module mainly operates as a FastCGI application in the
`AUTHORIZER` role, intended to plug into Apache's `mod_authnz_fcgi` or
any workalike, and configured in the server just as one would any
other authentication module. In addition to the authentication module,
there a couple of dynamic pages (namely login, logout) that need to be
surfaced as well. (Their locations are configurable.)

When unauthenticated users hit the protected area, they are met with a
form entreating them to enter their e-mail address. When they submit
the form, they are mailed a link with a random token attached to it
that provides the authentication. When the user visits the link, the
authentication handler trades the token attached to the URL (marking
it as used in the process) for a cookie. Responses to subsequent
requests then match the cookie to the user's e-mail address, and use
that to populate the `REMOTE_USER` field, which can then be picked up
by any downstream authorization handler or Web application.

Users of this system must be pre-authorized. The `lazyauth-cli`
command-line tool that ships with this package has a verb for doing
this. Since the primary use case for this module is client extranets,
and it is customary that everybody at Widgets, Inc., will have a
`@widgets.biz` address, entire e-mail domains can be mapped to Web
domains. In other words, you can say "grant access to anybody at
widgets dot biz to `widgets-inc.extranet.my.company`", and then not
have to think subsequently about whether this or that person at the
company has access.

> Also, if necessary, specific addresses can be blocked.

This module uses an SQL database as its primary storage mechanism. It
has been tested with SQLite and PostgreSQL, though in principle it
should work with anything for which there is a
[Sequel](https://sequel.jeremyevans.net/) driver. Use of SQLite is
discouraged in production, due to its well-known inability to handle
concurrent transactions. There is a secondary storage in the module
itself for the little over a dozen user interface templates.  The
locations of these (and thus their contents) can be overridden in a
configuration file, along with a number of other parameters, a few of
which (e.g., data source name, e-mail sender) are necessary for the
module to operate.

## Usage

To start using LazyAuth, we'll assume you have done the necessary
setup on the server (below), as well as all the necessary setup for an
address to send e-mail from. After that, we'll need a database (this
example uses PostgreSQL; you can of course skip this step for SQLite):

    $ createdb lazyauth

Now we initialize the configuration file and create the tables:

    $ lazyauth-cli -c ~/.lazyauth.yml init -d postgres:///lazyauth \
    -f noreply@my.company

> Note: the `init` command uses the `-c` flag as the location to
> _write_ a _new_ configuration file, while all other commands use the
> flag as the source to _read_ from an existing one. The program
> otherwise looks for `lazyauth.yml` in the current directory.

Now we privilege some e-mail addresses:

    $ lazyauth-cli -c ~/.lazyauth.yml privilege \
    -d widgets-inc.extranet.my.company widgets.biz some@other.person

Now, assuming we have configured the server, we start the daemon:

    $ lazyauth-cli -c ~/.lazyauth.yml fcgi
    Running authenticator daemon on fcgi://localhost:10101/

> You can use `-z` to detach the process. Listener IP and port are of
> course also configurable.

## Server Configuration

Currently the only known receptacle for this module is
`mod_authnz_fcgi`, which ships with Apache, though the interface is
standard (to the extent that FastCGI is a standard), and so in
principle it is usable in other systems. What follows is the
configuration for Apache 2.4.x or newer.

First, we need to declare the authenticator (here it can be called
anything but we are appropriately calling it `LazyAuth`) and where
it's listening:

```apache
AuthnzFcgiDefineProvider authn LazyAuth fcgi://localhost:10101/
```

> On Debian systems and their derivatives, this is in a separate file,
> `mods-available/authnz_fcgi.conf`. Note that you will also have to
> `a2enmod authnz_fcgi` or none of this configuration will work.

Then, in the virtual host (or main server configuration in lieu
thereof), we can use any standard configuration mechanism we want to
delineate the protected area. We invoke the module with the
`AuthnzFcgiCheckAuthnProvider` directive, and then tune it with
`Require`. `mod_authnz_fcgi` has a number of idiosyncrasies, one of
which is that it always must return a user, so we have to give it a
throwaway user like `nobody`, and then subsequently deny that user. (I
would consider this a design flaw in `mod_authnz_fcgi`.) The
expression `%{reqenv:FCGI_USER}` (where the slug `FCGI_USER` is
configurable on our side) is how the identity gets transmitted
upstream from LazyAuth to the server.

```apache
<Location /protected>
  # unfortunately mod_authnz_fcgi won't let you have a blank default user
  AuthnzFcgiCheckAuthnProvider LazyAuth Authoritative On RequireBasicAuth Off UserExpr "%{reqenv:FCGI_USER}" DefaultUser nobody
  <RequireAll>
    Require valid-user
    # that's fine, we just outlaw 'nobody'
    Require not user nobody
  </RequireAll>
</Location>
```

Another idiosyncrasy of `mod_authnz_fcgi` is that while it uses the
`200` response code to indicate a success, the _actual_ response back
to the client necessarily has to come from the downstram content
handler. As such, any other information from a _successful_
authentication response needs to be smuggled out through environment
variables. Since LazyAuth performs a redirect to remove the
authentication token from the URL upon successful authentication, the
following `mod_rewrite` configuration needs to be in place to turn the
environment variable back into an actual redirect:

```apache
RewriteCond %{ENV:FCGI_REDIRECT} .+
RewriteRule .* %{ENV:FCGI_REDIRECT} [R=307,L,QSD]
```

> Note that `mod_rewrite` syntax is different from `ap_expr` syntax,
> and the prefix `ENV` is used in the expression instead of `reqenv`
> above. We also use `QSD` to remove the query string from the
> _currently-requested_ URI, and redirect with `307` to preserve the
> request method.

We also need to account for _unsuccessful_ responses from the
authentication module, since certain headers (notably `Content-Type`)
are either getting overwritten by an unfortunate interaction with the
default error handler, or are otherwise not being transmitted (which
would be another bug in `mod_authnz_fcgi`).

```apache
Header always set Content-Type "expr=%{resp:Variable-FCGI_CONTENT_TYPE}" "expr=%{resp:Variable-FCGI_CONTENT_TYPE} != ''"
Header always unset Variable-FCGI_CONTENT_TYPE
```

Finally, the module provides two dynamic resources that need to be
mapped to content handlers; here we use `mod_proxy_fcgi` (remember to
enable it):

```apache
ProxyPass /email-link fcgi://localhost:10101/email-link
ProxyPass /logout     fcgi://localhost:10101/logout
```

> An earlier design had these operations controlled by `POST`
> parameters and were thus ostensibly not necessary, however it turns
> out that `mod_authnz_fcgi` does not convey request body content to
> the downstream FastCGI script, causing the latter to crash with a
> protocol error. While the handling is less than delicate, this is
> actually a reasonable expectation, as request bodies are only read
> once off the wire and will thus be already consumed (whether or not
> they contain the fields to which LazyAuth is sensitive) when the
> content handler is invoked. (The way Apache handles the request
> body, it /can/ be duplicated and reinserted into the input stream,
> but that is a whole project unto itself.

## Templates

LazyAuth has a number of UI states that are embedded in the gem. These
take the form of template files. The functionality of these templates
is currently at the absolute bare minimum required to do the job. The
templates are XHTML, with a basic placeholder substitution
functionality, which can take place either in processing instructions
(`<?var $WHATEVER?>`), or attribute values (`<elem
attr="$WHATEVER"/>`).

> I did this deliberately for a few reasons, the first being that the
> substitutions occur in a way such that the input _and_ the output
> always validates, i.e., there is no way to produce broken markup.
> The second is that this system neither needs nor merits a more
> sophisticated templating system. Each state is directly addressable;
> it gets its own template file. Anything that needs to be addressed
> in any individual state, save for a small number of substitutions in
> text nodes or attribute values, can be done by supplanting its file
> with a different one. Any styling or page composition needed to knit
> these states into their surroundings can be handled through an
> exterior mechanism, which I will endeavour to write up separately. I
> may consider different or additional template mechanisms
> (e.g. markdown, or any of the zillion non-standard template engines)
> at some point in the future.

The configuration parameter `transform` under `templates` will cause
an `xml-stylesheet` processing instruction to be inserted into all
outgoing templates with the location of an XSLT stylesheet, enabling
arbitrary manipulations (and also the main reason why these templates
are XHTML,).

> **NOTE 2022-04-22** this `lazyauth-cli extract` business is still
> under construction.

The default templates for all states are embedded in the gem
distribution, and can be overridden individually or en masse in the
configuration file by specifying the location of a supplanting file.
The command-line verb `lazyauth-cli extract $DESTINATION` will extract
the full set of templates from the gem, and deposit copies of them
wherever you tell it to.

In addition to these templates that get piped out from arbitrary
locations, there are a couple resources, namely two logout states
(`/logged-out` for current device; `/logged-out-all` for all devices),
which can be completely static. Boilerplate for these states is
included in the distribution and can be retrieved by running
`lazyauth-cli extract --static`. The URLs of these resources can
naturally be overridden in the configuration file.

> Out of an abundance of prudence I should also remark that to
> eliminate file extensions in static resources (at least in Apache),
> enable `mod_negotiation` and add `MultiViews` to any `Options`
> directive in scope.

What follows is the list of states, when they show up, and roughly
what they say. Most of them are specific error conditions:

### `default_401` (currently handled by `basic-401.xhtml`)

This page is the one everybody sees when they are not logged in,
unless a more specific page is more appropriate. It explains that the
area is protected, and the way to get access (assuming that you're on
the list) is to enter your e-mail address. It then provides said
form. Note that the `action=` of the form **must** point to the
location of the `email-link` resource, and there must also be a hidden
form field by the name of `forward` that contains the current URL.

### `default_404` (currently handled by `basic-404.xhtml`)

This resource should actually never be seen, as it currently only
arises when outside content-handling traffic is directed to locations
other than the two specified by LazyAuth.

### `knock_bad` (currently handled by `basic-409.xhtml`)

This is shown when the knock-knock token attached to the URL is
malformed. It is an undifferentiated `409 Conflict` message, which
also includes a form like the one found in the default `401`.

### `knock_not_found` (currently handled by `basic-409.xhtml`)

This is shown when the token is _not_ malformed, but also not present
in the database. (This is treated as a `403 Forbidden`, but the error
message is not meaningfully different from `409`, so it gets the same
message by default.)

### `knock_expired` (currently handled by `nonce-expired.xhtml`)

Here, the token attached to the link sent out in the e-mail has
expired, i.e., the user has not claimed it in time (by default, 10
minutes). Again we notify themm, and show them the form to generate a
new one.

### `cookie_bad` (currently handled by `basic-409.xhtml`)

This recapitulates the `knock_bad` scenario, but with a cookie.

### `cookie_not_found` (currently handled by `basic-409.xhtml`)

The cookie equivalent of `knock_not_found`.

### `cookie_expired` (currently handled by `cookie-expired.xhtml`)

This message is shown when the user has a cookie which has been
invalidated either by a logout or has been expired on the server
side. The user is given an opportunity to log back in.

### `no_user` (currently handled by `not-on-list.xhtml`)

This message is returned when the cookie is valid but the user is not,
e.g. their access was revoked since they hit the site last. They are
given an opportunity to log back in.

### `forward_bad` (currently handled by `uri-409.xhtml`)

This message is shown as the result of the user submitting their
e-mail when the forwarding address (URL), which should have been
included in the submitted form, is malformed (e.g. does not match the
domain). This is nominally a client error but it should never be
reached by normal operation. The only way a user would get here is a
misconfiguration on our part, or an attempt at abuse. We tell them to
go back and try again.

### `email` (currently handled by `email.xhtml`)

This is the actual e-mail that gets sent to the user. Note that the
`<title>` gets turned into the subject, and the entire thing is also
stripped to plain text.

### `email_bad` (currently handled by `email-409.xhtml`)

This status is returned after a user submits an e-mail address that is
syntactically bad.

### `email_not_listed` (currently handled by `not-on-list.xhtml`)

This happens when the e-mail address is not on the permit list. Users
are given an opportunity to try a different one.

### `email_failed` (currently handled by `basic-500.xhtml`)

This happens when the e-mailing process _itself_ fails, e.g. when the
script can't connectd to the specified SMTP server.

### `email_sent` (currently handled by `email-sent.xhtml`)

This is the confirmation page people see when LazyAuth has accepted
their e-mmail address and sent the link-containing e-mail.

### `post_only` (currently handled by `post-405.xhtml`)

This error only occurs when somebody tries to access one of the two
targets (by default `/email-link` and `/logout`) by a request method
other than `POST`, which should never happen outside of normal operation.

## All Configuration Options

### `host`

The host to listen on; defaults (as expected) to `localhost`.

### `port`

The TCP port, default `10101`.

### `state`

This is the configuration group involving the persistent state,
i.e. the database.

* `dsn` is the DSN (data source name), i.e., the connection string
  that gets passed into Sequel.
* `user` is the user name, which can be rolled into the DSN or
  separated out.
* Same goes for the `password`.
* `options` are additional options that get passed directly to the
  Sequel constructor.
* `expiry` deals with the expiration times of the different kinds of
  token, which are represented as ISO 8601 durations:
  * `query` handles the expiry for the token in the link's query
    string, defaulting to 10 minutes (`PT10M`)
  * `cookie` handles the expiry for the cookie, defaulting to two weeks
    (which gets refreshed by accessing the site; `P2W`)

### `keys`

These are overrides for different keys in query strings and HTML
forms.

* `query` is the key for the URL query string component that contains
  the nonce token; it defaults to `knock`.
* `cookie` is the key for the cookie, which defaults to `lazyauth`.
* `email` is the form key for the e-mail address, defaulting to `email`.
* `logout` is the form key for whether to log out all tokens or just
  the current one, defaulting to `logout`.

### `vars`

These are overrides for the names of the environment variables that
are handed back to `mod_authnz_fcgi`, in case anything collides with
an existing setup and needs to be called something else.

* `user`is what gets retrieved and turned into `REMOTE_USER`,
  defaulting to `FCGI_USER`.
* `redirect` is what gets retrieved and turned into a `Location:`
  header, defaulting to `FCGI_REDIRECT`.
* `type` is what gets retrieved and turned into a `Content-Type:`
  header, defaulting to `FCGI_CONTENT_TYPE`.

### `targets`

These are (relative, but not necessarily) URLs to pages that perform
specific functions within the system, and have a stable location.

* `login` is the target that accepts the `POST` request from the `401`
  page and others, that sends the e-mail and issues a confirmation. It
  defaults to `/email-link`. This resource is powered by LazyAuth and
  is used internally to configure the location of that resource.
* `logout` is the target that accepts the `POST` request to log
  out. It (rather predictably) defaults to `/logout`. This location is
  also handled by LazyAuth.
* `logout_one` is a _static_ (or other arbitrary) target (i.e., _not_
  handled by LazyAuth) that confirms the user has logged out their
  current session. It defaults to `/logged-out`.
* `logout_all` is another static target that confirms the user has
  logged out of all devices.

### `templates`

This is configuration for the various templates.

* `path` is the template root, that defaults to `content/` under the
  gem root.
* `transform` is the URL of an XSLT stylesheet. Omitted if omitted.
* `mapping` is a key-value structure of templates (listed above) to
  file names, relative to `path`.

### `email`

This is configuration for the e-mail sender.

* `from` is the sender's address; it has no default.
* `method` is how the sender will send mail, defaults to `sendmail`.
* `options` is a key-value structure of additional options, e.g. for
  when the `method` is `smtp`. It is fed directly into
  `Mail::Message#delivery_method`.

## Minimal Configuration

This is the absolute bare minimum configuration you will need supply
directly. All other values have defaults:

```yaml
state:
  dsn: whatever://database
templates:
  # this is actually optional, but there is no default value.
  transform: /transform.xsl
email:
  from: robot@my.company
  # additional SMTP configuration would go here, if applicable.
```

## Installation

You know how to do this:

    $ gem install lazyauth

Or, [download it off rubygems.org](https://rubygems.org/gems/lazyauth).

## Contributing

Bug reports and pull requests are welcome at
[the GitHub repository](https://github.com/doriantaylor/rb-lazyauth).

## Copyright & License

©2019-2022 [Dorian Taylor](https://doriantaylor.com/)

This software is provided under
the [Apache License, 2.0](https://www.apache.org/licenses/LICENSE-2.0).
