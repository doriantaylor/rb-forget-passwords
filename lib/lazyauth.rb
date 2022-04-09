require 'lazyauth/version'
require 'lazyauth/state'
require 'lazyauth/template'
require 'uuid-ncname'

require 'rack'
require 'rack/request'
require 'rack/response'

require 'mail'

module LazyAuth

  # An error response (with status, headers, etc) that can be raised
  # and caught.
  class ErrorResponse < RuntimeError

    attr_reader :response

    # Create a new error response.
    #
    # @param body [#to_s, #each] the response body
    # @param status [Integer] the HTTP status code
    # @param headers [Hash] the header set
    #
    def initialize body = nil, status = 500, headers = {}
      if body.is_a? Rack::Response
        @response = body
      else
        @response = Rack::Response.new body, status, headers
      end
    end

    # Returns the error message (which is the response body).
    #
    # @return [String] the error message (response body)
    #
    def message
      @response.body
    end

    # Sets a new error message (response body). Does not change
    # anything else, like headers or status or anything.
    #
    # @param msg [#to_s] the new error message
    #
    def message= msg
      @response.body = msg.to_s
    end

    # Generate a new exception with a Rack::Response as a message.
    # Otherwise creates a new error response.
    #
    # @param message [Rack::Response, #to_s] the response object or string
    #
    # @return [LazyAuth::ErrorResponse] a new error response
    #
    def self.exception message
      # XXX TODO auto generate (x)html from text message?
      case message
      when Rack::Response then self.new message
      else
        self.new message.to_s, 500, { 'Content-Type' => 'text/plain' }
      end
    end

    # Returns itself if the message is nil. Otherwise it runs the
    # class method with the message as its argument.
    #
    # @param message [nil, Rack::Response, #to_s] optional response
    #  object or string
    #
    # @return [LazyAuth::ErrorResponse] a new error response
    #
    def exception message = nil
      return self if message.nil?
      self.class.exception message
    end
  end

  class Middleware
    # lol jk it's not a middleware yet. let's get the app running
    # first and then we can break it in two.
  end

  class App
    require 'time'
    require 'uri'

    require 'uuidtools'
    require 'uuid-ncname'

    private

    TWO_WEEKS = ISO8601::Duration.new('P2W').freeze

    XPATHNS = { html: 'http://www.w3.org/1999/xhtml' }.freeze

    # Return a token suitable for being either a nonce or a cookie.
    # Returns a compact UUID.
    #
    # @return [String] a compact UUID.
    #
    def make_token
      UUID::NCName.to_ncname UUIDTools::UUID.random_create, version: 1
    end

    # Return a copy of the given URI with the nonce token in the
    # `knock` parameter.
    #
    # @param uri [URI] the desired base URI
    # @param token [#to_s] the token
    #
    # @return [URI] the new URI
    #
    def make_login_link uri, token
      key = @keys[:query].to_s
      # strip off any old one
      query = URI.decode_www_form(uri.query || '').reject do |pair|
        pair.first == key
      end

      # append the new one
      query << [key, token]

      # add to uri
      uri = uri.dup
      uri.query = URI.encode_www_form query

      uri
    end

    # Return an absolute request-URI from the Rack::Request.
    #
    # @param req [Rack::Request] the request object
    #
    # @return [URI] the full URI.
    #
    def req_uri req
      URI(req.base_url) + req.env['REQUEST_URI']
    end

    # Return a copy of the given URI minus zero or more query parameters.
    #
    # @param uri [URI] the URI
    # @param *key [Array<#to_s>] the query key(s) to remove
    #
    # @return [URI] the new URI
    #
    def uri_minus_query uri, *key
      return uri unless uri.query
      uri = uri.dup
      key = key.map(&:to_s)

      query = URI.decode_www_form(uri.query || '').reject do |pair|
        key.include? pair.first
      end
      uri.query = query.empty? ? nil : URI.encode_www_form(query)
      uri
    end

    # Test whether the token is well-formed.
    #
    # @return [true, false] the well-formedness of the token
    #
    def token_ok? token
      !!UUID::NCName.valid?(token)
    end

    # Expire a token.
    #
    def expire token
      @state.token.expire token
    end

    # Extract an e-mail address from a string, or otherwise return nil.
    #
    # @param string [#to_s] presumably a string
    #
    # @return [Mail::Address, nil] maybe an e-mail address.
    #
    def email_in string
      return nil unless string.to_s.include? ?@
      begin
        Mail::Address.new string.to_s.strip.downcase
      rescue Mail::Field::IncompleteParseError
        nil
      end
    end

    # Send the e-mail containing the link.
    #
    #
    def send_link req, address
      # set up the variables
      uri = req_uri req
      vars = {
        URL:        uri.to_s,
        PRETTY_URL: uri.to_s.sub(/^https?:\/\/(.*)\/?$/i, "\1"),
        KNOCK_URL:  make_login_link(uri, token),
        DOMAIN:     req.base_url.host,
        EMAIL:      address.to_s,
      }

      # grab the template since we'll use it
      template = @templates[:email]

      # process the templates
      doc = template.process vars
      sub = doc.xpath('normalize-space((//title|//html:title)[1])', XPATHNS)

      html = template.serialize doc, { 'Content-Type' => 'text/html' }
      text = template.serialize doc, { 'Content-Type' => 'text/plain' }

      Mail.new do
        from @email[:from]
        to address
        subject sub
        html_part html
        text_part text
        delivery_method @email[:method], **(@email[:options] || {})
      end.deliver
    end

    # @!group Actual Handlers

    def handle_knock req, token
      resp = Rack::Response.new

      unless token_ok? token
        resp.status = 409
        @templates[:knock_bad].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      unless user = @state.user_for(token)
        resp.status = 403
        @templates[:knock_not_found].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      # stamp the knock token so we know not to use it again
      @state.stamp_token knock, req.ip

      # remove existing cookie
      if (token = req.cookies[cookie_key])
        @state.token.expire token
        resp.delete_cookie cookie_key, { value: token }
      end

      uri    = req_uri req
      target = uri_minus_query uri, query_key

      # we never use the knock token again so we can overwrite it with
      # a new cookie
      token = @state.new_token user, cookie: true

      # set the user and redirect location as variables
      resp.set_header "Variable-#{user_var}", user
      resp.set_header "Variable-#{redirect_var}", target.to_s
      resp.set_cookie cookie_key, {
        value: token, expires: Time.at(2**31-1),
        secure: req.ssl?,  httponly: true,
      }

      # response has to be 200 or the auth handler won't pick it up
      # (response is already 200 by default)

      # content-length has to be present but empty or it will crap out
      resp.set_header 'Content-Length', ''

      resp
    end

    def handle_cookie req, token
      resp = Rack::Response.new

      unless token_ok? token
        resp.status = 409
        @templates[:cookie].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      unless user = @state.user_for(token, cookie: true)
        resp.status = 403
        @templates[:no_user].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      # stamp the token
      @state.stamp_token token, req.ip

      # just set the variable
      resp.set_header "Variable-#{user_var}", user

      # content-length has to be present but empty or it will crap out
      resp.set_header 'Content-Length', ''

      resp
    end

    def handle_login req
      uri  = req_uri req
      resp = Rack::Response.new

      # obtain the email address from the form
      unless address = email_in(req.POST[email_key])
        resp.status = 409
        @templates[:email_bad].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      # check the email against the list
      unless @state.acl.listed? uri, address
        resp.status = 401
        @templates[:email_not_listed].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      # XXX TODO consider rate-limiting so as not to bombard the
      # target with emails; return either 429 (too many requests) or
      # perhaps the new code 425 (too early)

      # send the email
      unless send_link address
        resp.status = 500
        @templates[:email_failed].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      # return 401 still but with 'check email' body
      @templates[:default_401].populate resp, req
    end

    def handle_logout req, all
      all = /^\s*(1|true|on|yes)\s*$/i.match? all.to_s

      resp = Rack::Response.new

      if token = req.cookies[cookie_key]
        # invalidate the token associated with the cookie
        @state.token.expire token
        # clear the cookie
        resp.delete_cookie cookie_key, { value: token }
      end

      # we do when we actually process the token in the query string
      resp.status   = 303
      resp.location = (req.base_url +
        @targets[all ? :logout_one : :logout_all]).to_s

      resp
    end

    def handle_post req
      if logout = req.POST[logout_key]
        handle_logout req, logout
      elsif email = req.POST[email_key]
        handle_login req, email
      else
        default_401 req
      end
    end

    # @!endgroup

    public

    # we want all these constants to be public so they show up in the docs
    DEFAULT_KEYS = { query: 'knock', cookie: 'lazyauth',
      email: 'email', logout: 'logout' }.freeze
    DEFAULT_VARS = { user: 'FCGI_USER', redirect: 'FCGI_REDIRECT'}.freeze
    DEFAULT_PATH = (Pathname(__FILE__) + '../content').expand_path.freeze
    DEFAULT_MAIL = {
      type: :smtp, from: nil, host: 'localhost', port: 25 }.freeze

    attr_reader :query_key, :cookie_key, :email_key, :logout_key,
      :user_var, :redirect_var


    def initialize dsn, keys: DEFAULT_KEYS, vars: DEFAULT_VARS,
        path: DEFAULT_PATH, templates: DEFAULT_TEMPLATES, mail: DEFAULT_MAIL,
        expires: TWO_WEEKS, debug: false

      @debug = debug

      @keys = keys
      @vars = vars

      @templates = templates.is_a?(LazyAuth::Template::Mapper) ? templates :
        LazyAuth::Template::Mapper.new(path, templates)
      @templates.verify! :email

      @query_key    = query_key
      @cookie_key   = cookie_key
      @user_var     = user_var
      @redirect_var = redirect_var

      @state = State.new dsn, debug: debug
    end

    def call env
      # do surgery to request sceme
      if env['REQUEST_SCHEME']
        env['HTTPS'] = 'on' if env['REQUEST_SCHEME'].downcase == 'https'
      end
      req  = Rack::Request.new env
      uri  = URI(req.base_url) + env['REQUEST_URI']
      resp = Rack::Response.new

      # keep this around for when we split this into app and middleware

      # unless env['FCGI_ROLE'] == 'AUTHORIZER'
      #   resp.status = 500
      #   resp.body << "LazyAuth::App only works as a FastCGI authorizer!"
      #   return resp.finish
      # end

      warn env.inspect if @debug

      begin
        # handle knock
        resp = if knock = req.GET[@keys[:query]]
                 handle_knock req, knock
               elsif token = req.cookies[@keys[:cookie]]
                 handle_cookie req, token
               elsif req.post?
                 handle_post req
               else
                 default_401 req
               end
      rescue LazyAuth::ErrorResponse => e
        resp = e.response
      end

      return resp.finish

      # handle POSTs (login, logout)

      # otherwise 401

      # obtain the query string
      if (knock = req.GET[@keys[:query]])
        # return 409 unless the knock parameter is valid
        unless token_ok? knock
          resp.status = 409
          resp.write 'boo hoo bad knock parameter'
          return resp.finish
        end

        # return 403 if the knock parameter doesn't pick a user

        user = @state.user_for knock
        unless user
          resp.status = 403
          resp.write "Could not find a user for token #{knock}."
          return resp.finish
        end

        @state.stamp_token knock, req.ip

        # remove existing cookie
        if (token = req.cookies[cookie_key])
          @state.token.expire token
          resp.delete_cookie cookie_key, { value: token }
        end

        target = uri_minus_query uri, @keys[:query]

        token = @state.new_token user, cookie: true

        # set the user and redirect location as variables
        resp.set_header "Variable-#{@vars[:user]}", user
        resp.set_header "Variable-#{@vars[:redirect]}", target.to_s
        resp.set_cookie @keys[:cookie], {
          value: token, expires: Time.at(2**31-1),
          secure: req.ssl?,  httponly: true,
        }

        # response has to be 200 or the auth handler won't pick it up
        # (response is already 200 by default)

        # content-length has to be present but empty or it will crap out
        resp.set_header 'Content-Length', ''

      elsif (token = req.cookies[cookie_key])
        # return 409 unless the cookie is valid
        unless token_ok? token
          resp.status = 409
          resp.write 'boo hoo bad token'
          return resp.finish
        end

        # return 403 if the cookie doesn't pick a user
        user = @state.user_for token, cookie: true
        unless user
          resp.status = 403
          resp.write "Could not find a user for token #{knock}."
          return resp.finish
        end

        # stamp the token
        @state.stamp_token token, req.ip

        # just set the variable
        resp.set_header "Variable-#{user_var}", user

        # content-length has to be present but empty or it will crap out
        resp.set_header 'Content-Length', ''
      else
        # return 401
        resp.status = 401
        resp.set_header 'Content-Type', 'text/plain'
        out = (['boo hoo'] * 1025).join(' ')
        resp.set_header 'Content-Length', out.b.length.to_s
        resp.write out
        warn 'doublyou tee eff'
        return resp.finish
      end

      resp.finish
    end
  end
end
