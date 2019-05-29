# LazyAuth - Web Authentication, but lazy

This little [Rack middleware](https://github.com/rack/rack/wiki/List-of-Middleware) (and attendant command line tool and rackup app) exists for the
purpose of providing rudimentary access control to a website when the
prospective users are both small in number, and very busy. It
circumvents schmucking around provisioning passwords by generating a
link which you can pass to each of your users through some other
mechanism, that when visited logs them in and keeps them logged in as
long as you want. This is basically the equivalent of having a "forgot
password" link without anybody having to click on "forgot password",
and is perfectly adequate security in certain contexts, namely the
ones [I](https://doriantaylor.com/) am interested in.

## Rationale

I have various Web properties littered around the internet in various
stages of development. Sometimes I want to show them to people, but
only _certain_ people, but I _don't_ want to spend my life managing
user accounts. Moreover, since the long tail of internet
authentication is a **forgot my password** link, I figure let's just
cut to the chase and hand those out instead.

## Usage

This is what it would look like to generate a LazyAuth link, assuming
you had everything else set up:

    $ lazyauth-cli -c lazyauth.yml bob https://mysite.derp/private
    https://mysite.derp/private?knock=E4FJfQvFeBZJ6HLx9PCLtK

Now you DM, text, or email this link to Bob. When Bob clicks on the
link, LazyAuth will set a cookie, and when it sees the cookie again,
it will set the request's `user` field and `REMOTE_USER` environment
variable to `bob`. This can subsequently be picked up by whatever
other authentication framework is present in your system.

## Setting Up

First, you're going to need somewhere to put your data:

    $ lazyauth-cli init -b https://mysite.derp/ -d sqlite://lazyauth.db
    Created configuration file and state database.
    $

You can use LazyAuth in your Rack app, but it can also serve as a
standalone authenticator, using [a little-known feature of the FastCGI
spec](https://github.com/fast-cgi/spec/blob/master/spec.md#63-authorizer).
Here is roughly what [the Apache (2.4)
configuration](https://httpd.apache.org/docs/2.4/mod/mod_authnz_fcgi.html)
for such a beast would look like:

```apache
# we assume you have loaded mod_authnz_fcgi

# define this somewhere
AuthnzFcgiDefineProvider authn LazyAuth fcgi://localhost:10101/

# this is whatever you want to lock down
<Location /protected>
  # unfortunately mod_authnz_fcgi won't let you have a blank default user
  AuthnzFcgiCheckAuthnProvider LazyAuth Authoritative On RequireBasicAuth Off UserExpr "%{reqenv:FCGI_USER}" DefaultUser nobody
  <RequireAll>
    Require valid-user
    # that's fine, we just outlaw 'nobody'
    Require not user nobody
  </RequireAll>

  # we will also need to smuggle out any redirection that happens; 
  # note the use of ENV instead of reqenv and the QSD flag. I also use
  # the 307 response code here to indicate the request method ought to
  # be preserved across redirects.
  RewriteCond %{ENV:FCGI_REDIRECT} .+
  RewriteRule .* %{ENV:FCGI_REDIRECT} [R=307,L,QSD]
</Location>
```

> Note: I am not sure at this time if other servers (e.g. NginX,
> lighttpd) have this capability. If not, file your bug with _them_!

Now run the authenticator:

    $ lazyauth-cli fcgi -c lazyauth.yml
    Running authenticator daemon on fcgi://localhost:10101/
    $

> Note: You may want to put some kind of watcher on this process; if
> it ever happens to crash, your website will hurl `500` errors until
> you fix it.

## Installation

You know how to do this:

    $ gem install lazyauth

Or, [download it off rubygems.org](https://rubygems.org/gems/lazyauth).

## Contributing

Bug reports and pull requests are welcome at
[the GitHub repository](https://github.com/doriantaylor/rb-lazyauth).

## Copyright & License

©2019 [Dorian Taylor](https://doriantaylor.com/)

This software is provided under
the [Apache License, 2.0](https://www.apache.org/licenses/LICENSE-2.0).
