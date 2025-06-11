require 'forget-passwords/version'
require 'forget-passwords/types'
require 'forget-passwords/state'
require 'forget-passwords/template'
require 'uuid-ncname'

require 'dry-types'
require 'dry-schema'

require 'rack'
require 'rack/request'
require 'rack/response'

require 'base64'
require 'mail'

module ForgetPasswords

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
    # @return [ForgetPasswords::ErrorResponse] a new error response
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
    # @return [ForgetPasswords::ErrorResponse] a new error response
    #
    def exception message = nil
      return self if message.nil?
      self.class.exception message
    end
  end

  class App
    require 'time'
    require 'uri'

    require 'uuidtools'
    require 'uuid-ncname'

    private

    TEN_MINUTES = ISO8601::Duration.new('PT10M').freeze
    TWO_WEEKS   = ISO8601::Duration.new('P2W').freeze

    XPATHNS = { html: 'http://www.w3.org/1999/xhtml' }.freeze

    # we want all these constants to be public so they show up in the docs
    DEFAULT_KEYS = { query: 'knock', cookie: 'forgetpw',
      email: 'email', logout: 'logout' }.freeze
    DEFAULT_VARS = { user: 'FCGI_USER', redirect: 'FCGI_REDIRECT'}.freeze
    DEFAULT_PATH = (Pathname(__FILE__) + '../../content').expand_path.freeze

    SH = ForgetPasswords::Types::SymbolHash
    ST = ForgetPasswords::Types::String
    AT = ForgetPasswords::Types::ASCIIToken

    Keys = SH.schema({
      query:   'knock',
      cookie:  'forgetpw',
      email:   'email',
      logout:  'all',
      forward: 'forward',
    }.transform_values { |x| AT.default x.freeze }).hash_default

    Vars = SH.schema({
      user:     'FCGI_USER',
      redirect: 'FCGI_REDIRECT',
      type:     'FCGI_CONTENT_TYPE',
      jwt:      'FCGI_JWT',
    }.transform_values { |x| AT.default x.freeze }).hash_default

    Targets = SH.schema({
      login:      '/email-link',
      logout:     '/logout',
      logout_one: '/logged-out',
      logout_all: '/logged-out-all',
    }.transform_values { |x| ST.default x.freeze }).hash_default

    # mapping override with specific values
    Mapping = SH.schema({
      default_401:      'basic-401.xhtml',
      default_404:      'basic-404.xhtml',
      default_409:      'basic-409.xhtml',
      default_500:      'basic-500.xhtml',
      knock_bad:        'basic-409.xhtml',
      knock_not_found:  'basic-409.xhtml',
      knock_expired:    'nonce-expired.xhtml',
      cookie_bad:       'basic-409.xhtml',
      cookie_not_found: 'basic-409.xhtml',
      cookie_expired:   'cookie-expired.xhtml',
      no_user:          'not-on-list.xhtml',
      forward_bad:      'uri-409.xhtml',
      email:            'email.xhtml',
      email_bad:        'email-409.xhtml',
      email_not_listed: 'not-on-list.xhtml',
      email_failed:     'basic-500.xhtml',
      email_sent:       'email-sent.xhtml',
      post_only:        'post-405.xhtml',
    }.transform_values { |x| ST.default x.freeze }).hash_default

    # this is the closest thing to "inheritance"
    RawTemplates = ForgetPasswords::Template::Mapper::RawParams.schema(
      mapping: Mapping
    ).hash_default

    # which means we have to duplicate the constructor and its default
    Templates = ForgetPasswords::Types.Constructor(ForgetPasswords::Template::Mapper) do |x|
      if x.is_a? ForgetPasswords::Template::Mapper
        x
      else
        raw  = RawTemplates.(x)
        path = raw.delete :path
        ForgetPasswords::Template::Mapper.new path, **raw
      end
    end.default do
      raw  = RawTemplates.({})
      path = raw.delete :path
      ForgetPasswords::Template::Mapper.new path, **raw
    end

    EMail = SH.schema(
      from:      Dry::Types['string'],
      method:   ForgetPasswords::Types::Coercible::Symbol.default(:sendmail),
      options?: ForgetPasswords::Types::Hash.map(
        ForgetPasswords::Types::NormSym, ForgetPasswords::Types::Atomic)
    ).hash_default

    # JWT stuff

    JWTAlgo = Dry::Types['string'].default('HS256'.freeze).enum(*(
      %w[HS ES RS PS].product([256, 384, 512]).map(&:join) + %w[ES256K ED25519]))
    JWTConfig = SH.schema(
      algorithm?: JWTAlgo,
      secret:     Dry::Types['string'],
    ).hash_default

    # the composed configuration hash
    Config = SH.schema(
      state:     ForgetPasswords::State::Type,
      keys:      Keys,
      vars:      Vars,
      targets:   Targets,
      templates: Templates,
      email:     EMail,
      jwt?:      JWTConfig,
    ).hash_default

    # Return a token suitable for being either a nonce or a cookie.
    # Returns a compact UUID.
    #
    # @return [String] a compact UUID.
    #
    def make_token
      UUID::NCName.to_ncname UUIDTools::UUID.random_create
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
      # strip off any old key(s) that might be present
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

    # Return a Time object correctly delta'd by an {ISO8601::Duration}.
    #
    # @param duration [ISO8601::Duration] the duration
    # @param from [nil, Time] anchor time, if other than `Time.now`
    #
    # @return [Time] the new time
    #
    def time_delta duration, from = Time.now
      from.to_time.gmtime +
        duration.to_seconds(ISO8601::DateTime.new from.iso8601)
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

    # Send the e-mail containing the link to log in.
    #
    # @param req [Rack::Request] the HTTP request object
    # @param address [#to_s] the principal's e-mail address
    #
    # @return [Mail::Message] the message sent to the address.
    #
    def send_link req, email, uri
      # set up the variables
      uri ||= req_uri req
      # this can't be a oneoff if the recipient is behind barracuda or whatever
      token = @state.new_token email, oneoff: false
      vars  = {
        URL:        uri.to_s,
        PRETTY_URL: uri.to_s.sub(/^https?:\/\/(.*?)\/*$/i, "\\1"),
        KNOCK_URL:  make_login_link(uri, token),
        DOMAIN:     URI(req.base_url).host,
        EMAIL:      email.to_s,
        # EXPIRES:
      }

      # grab the template since we'll use it
      template = @templates[:email, req]

      # process the templates
      doc = template.process vars: vars
      sub = doc.xpath('normalize-space((//title|//html:title)[1])', XPATHNS)

      html = template.serialize doc, { 'Accept' => 'text/html'  }
      text = template.serialize doc, { 'Accept' => 'text/plain' }

      # fuuuuuu the block operates as instance_exec
      em = @email
      Mail.new do
        from      em[:from]
        to        email
        subject   sub
        html_part { content_type 'text/html'; body html }
        text_part { body text }
        delivery_method em[:method], **(em[:options] || {})
      end.deliver
    end

    def raise_error status, key, req, vars: {}
      uri = req_uri req
      resp = Rack::Response.new
      resp.status = status
      @templates[key, req].populate resp, req, vars, base: uri
      resp.set_header "Variable-#{@vars[:type]}", resp.content_type
      raise ForgetPasswords::ErrorResponse, resp
    end

    # @!group Actual Handlers

    def default_401 req
      uri  = req_uri req
      resp = Rack::Response.new
      resp.status = 401
      @templates[:default_401, req].populate resp, req, {
        FORWARD: req_uri(req).to_s, LOGIN: @targets[:login] }, base: uri
      resp.set_header "Variable-#{@vars[:type]}", resp.content_type
      resp
    end

    def maybe_set_jwt resp, user
      if (@jwt || {})[:secret]
        jwtok = JWT.encode({ sub: user.to_s }, @jwt[:secret], @jwt[:algorithm])
        resp.set_header "Variable-#{@vars[:jwt]}", jwtok

        jwtok
      end
    end

    def handle_knock req, token
      uri    = req_uri req
      target = uri_minus_query uri, @keys[:query]
      resp   = Rack::Response.new

      raise_error(409, :knock_bad, req) unless token_ok? token

      raise_error(401, :knock_expired, req,
        vars: { LOGIN: @targets[:login], FORWARD: target.to_s }) unless
        @state.token.valid? token, oneoff: false

      raise_error(403, :knock_not_found, req) unless
        user = @state.user_for(token)

      # stamp the knock token so we know not to use it again
      @state.stamp_token token, req.ip

      # remove existing cookie
      if (token = req.cookies[@keys[:cookie]])
        @state.token.expire token
        resp.delete_cookie @keys[:cookie] #, { value: token }
      end

      # we never use the knock token again so we can overwrite it with
      # a new cookie
      token = @state.new_token user, cookie: true

      # set the user and redirect location as variables
      resp.set_header "Variable-#{@vars[:user]}", user.to_s
      resp.set_header "Variable-#{@vars[:redirect]}", target.to_s if
        target != uri # (note this should always be true)

      maybe_set_jwt resp, user.to_s

      resp.set_cookie @keys[:cookie], {
        value: token, secure: req.ssl?, httponly: true,
        domain: uri.host, path: ?/, same_site: :lax, # strict is too strict
        expires: time_delta(@state.expiry[:cookie]),
      }

      # response has to be 200 or the auth handler won't pick it up
      # (response is already 200 by default)

      # content-length has to be present but empty or it will crap out
      resp.set_header 'Content-Length', ''

      resp
    end

    def handle_token req, token, now = Time.now
      resp = Rack::Response.new

      uri  = req_uri req

      vars = { LOGIN: @targets[:login], FORWARD: uri.to_s }

      # check if token is well-formed
      raise_error(409, :cookie_bad, req, vars: vars) unless token_ok? token

      # check if the cookie is still valid
      raise_error(401, :cookie_expired, req, vars: vars) unless
        @state.token.valid? token, cookie: true

      # check if there is an actual user associated with the cookie
      raise_error(403, :no_user, req, vars: vars) unless
        user = @state.user_for(token, record: true, cookie: true)

      raise_error(403, :email_not_listed, req, vars: vars) unless
        @state.acl.listed? uri, user.email

      @state.freshen_token token, from: now

      # stamp the token
      @state.stamp_token token, req.ip, seen: now

      # just set the variable
      resp.set_header "Variable-#{@vars[:user]}", user.principal.to_s

      maybe_set_jwt resp, user.principal.to_s

      # content-length has to be present but empty or it will crap out
      resp.set_header 'Content-Length', ''

      resp
    end

    def handle_cookie req, token = nil
      token ||= req.cookies[@keys[:cookie]]

      now  = Time.now
      resp = handle_token req, token, now
      uri  = req_uri req

      # update the cookie expiration
      resp.set_cookie @keys[:cookie], {
        value: token, secure: req.ssl?, httponly: true,
        domain: uri.host, path: ?/, same_site: :lax, # strict is too strict
        expires: time_delta(@state.expiry[:cookie], now),
      }

      resp
    end

    def handle_login req
      uri  = req_uri req
      resp = Rack::Response.new

      # check that the forwarding URI is well-formed and has the same
      # scheme/authority
      forward = uri + req.POST[@keys[:forward]] rescue nil
      raise_error(409, :forward_bad, req) unless forward and
        (forward = forward.normalize).host == uri.host

      vars = { LOGIN: @targets[:login].to_s, FORWARD: forward.to_s }

      # obtain the email address from the form
      raise_error(409, :email_bad, req, vars: vars) unless
        address = email_in(req.POST[@keys[:email]])

      # XXX TODO wrap this business in a transaction like an adult?

      # check the email against the list
      raise_error(401, :email_not_listed, req, vars: vars) unless
        @state.acl.listed? uri, address

      # XXX TODO consider rate-limiting so as not to bombard the
      # target with emails; return either 429 (too many requests) or
      # perhaps the new code 425 (too early)

      # find or create the user based on the email (this should never
      # fail, except internally)
      @state.new_user address

      # send the email
      begin
        send_link req, address, forward
      rescue StandardError => e
        # XXX generic logger???
        warn e.full_message
        warn caller

        # anyway,,,
        raise_error(500, :email_failed, req)
      end

      # return 200 now because this is now a content handler
      resp.status = 200
      @templates[:email_sent, req].populate resp, req, {
        FORWARD: forward.to_s, FROM: @email[:from].to_s, EMAIL: address.to_s },
        base: uri
    end

    def handle_logout req, all = nil
      all = req.GET[@keys[:logout]] if all.nil?
      all = /^\s*(1|true|on|yes)\s*$/i.match? all.to_s

      resp = Rack::Response.new

      # this does the actual "logging out"
      if token = req.cookies[@keys[:cookie]]
        if all and id = @state.token.id_for(token)
          # nuke all the cookies for the id
          @state.expire_tokens_for id
        else
          # invalidate the token associated with the cookie
          @state.token.expire token
        end
        # clear the cookie
        resp.delete_cookie @keys[:cookie] #, { value: token }
      end

      # otherwise this thing will pretend like you're logging out even
      # if you were never logged in

      # we do when we actually process the token in the query string
      resp.status   = 303
      resp.write 'Redirecting...'
      resp.location = (req_uri(req) +
        @targets[all ? :logout_one : :logout_all]).to_s

      resp
    end

    # Authenticate the request.
    #
    # @return [Rack::Response] a suitable response.
    #
    def handle_auth req
      auth = req.get_header('Authorization') || req.env['HTTP_AUTHORIZATION']
      if auth and !auth.strip.empty?
        # warn "has authorization header #{auth}"
        mech, *auth = auth.strip.split
        token = case mech.downcase
                when 'basic'
                  # can't trust/use rack here
                  Base64.decode64(auth.first || '').split(?:, 2).last
                when 'bearer'
                  auth.first
                end

        if token
          handle_token req, token
        else
          default_401 req
        end
      elsif knock = req.GET[@keys[:query]]
        # check for a knock; this overrides an existing cookie
        # warn "has knock token #{knock}"
        handle_knock req, knock
      # elsif req.post?
      #  # next check for a login/logout attempt
      #  handle_post req
      elsif token = req.cookies[@keys[:cookie]]
        # next check for a cookie
        # warn "has cookie #{token}"
        handle_cookie req, token
      else
        default_401 req
      end
    end

    def handle_content req
      uri = req_uri req
      if proc = @dispatch[uri.path]
        return instance_exec req, &proc
      else
        # return 404 lol
        raise_error(404, :default_404, req)
      end
    end

    # @!endgroup

    DISPATCH = {
      login: -> req {
        raise_error(405, :post_only, req) unless req.post?

        handle_login req
      },
      logout: -> req {
        raise_error(405, :post_only, req) unless req.post?

        handle_logout req
      },
    }

    public

    def initialize state, keys: {}, vars: {}, targets: {},
        templates: {}, email: {}, jwt: nil, debug: false

      @debug = debug

      # process config
      config = { state: state, keys: keys, vars: vars, targets: targets,
                templates: templates, email: email }
      config[:jwt] = jwt if jwt and !jwt.empty?
      config = Config.(config).to_h

      # then assign members
      config.each { |key, value| instance_variable_set "@#{key.to_s}", value }
      # XXX FIX COERCION
      config[:email][:options][:tls] = true if
        config.dig :email, :options, :tls

      if @jwt
        begin
          require 'jwt'
          require 'rbnacl' if %w[ED25519].include? @jwt[:algorithm]
        rescue LoadError => e
          if e.path == 'rbnacl'
            warn "The 'rbnacl' gem is required for ED25519."
          else
            warn "You have a JWT configured but no 'jwt' gem installed."
          end

          raise e
        end
      end

      #  @email.inspect

      # create a dispatch table for content requests
      # XXX this will have to be expanded for multiple hosts
      @dispatch = @targets.reduce({}) do |a, pair|
        if proc = DISPATCH[pair.first]
          a[pair.last] ||= proc
        end
        a
      end.compact.to_h

    end

    def call env
      # do surgery to request sceme
      if env['REQUEST_SCHEME']
        env['HTTPS'] = 'on' if env['REQUEST_SCHEME'].downcase == 'https'
      end
      req  = Rack::Request.new env
      resp = Rack::Response.new

      # keep this around for when we split this into app and middleware

      # unless env['FCGI_ROLE'] == 'AUTHORIZER'
      #   resp.status = 500
      #   resp.body << "ForgetPasswords::App only works as a FastCGI authorizer!"
      #   return resp.finish
      # end

      warn env.inspect if @debug

      begin
        resp = if env['FCGI_ROLE'] == 'AUTHORIZER'
                 handle_auth req
               else
                 handle_content req
               end
      rescue ForgetPasswords::ErrorResponse => e
        resp = e.response
      end

      return resp.finish
    end
  end
end
