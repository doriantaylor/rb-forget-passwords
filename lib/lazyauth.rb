require 'lazyauth/version'
require 'lazyauth/types'
require 'lazyauth/state'
require 'lazyauth/template'
require 'uuid-ncname'

require 'dry-types'
require 'dry-schema'

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

    TEN_MINUTES = ISO8601::Duration.new('PT10M').freeze
    TWO_WEEKS   = ISO8601::Duration.new('P2W').freeze

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
    def send_link req, address
      # set up the variables
      uri   = req_uri req
      token = @state.new_token address, oneoff: true
      vars  = {
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
        from            @email[:from]
        to              address
        subject         sub
        html_part       html
        text_part       text
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
      if (token = req.cookies[@keys[:cookie]])
        @state.token.expire token
        resp.delete_cookie @keys[:cookie], { value: token }
      end

      uri    = req_uri req
      target = uri_minus_query uri, @keys[:query]

      # we never use the knock token again so we can overwrite it with
      # a new cookie
      token = @state.new_token user, cookie: true

      # set the user and redirect location as variables
      resp.set_header "Variable-#{user_var}", user
      resp.set_header "Variable-#{redirect_var}", target.to_s
      resp.set_cookie @keys[:cookie], {
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
        @templates[:cookie_bad].populate resp, req
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
      unless address = email_in(req.POST[@keys[:email]])
        resp.status = 409
        @templates[:email_bad].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      # XXX TODO wrap this business in a transaction like an adult?

      # check the email against the list
      unless @state.acl.listed? uri, address
        resp.status = 401
        @templates[:email_not_listed].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      # XXX TODO consider rate-limiting so as not to bombard the
      # target with emails; return either 429 (too many requests) or
      # perhaps the new code 425 (too early)

      # find or create the user based on the email (this should never
      # fail, except internally)
      @state.new_user email

      # send the email
      begin
        send_link req, address
      rescue StandardError => e
        # XXX generic logger???
        warn e.inspect

        # anyway,,,
        resp.status = 500
        @templates[:email_failed].populate resp, req
        raise LazyAuth::ErrorResponse, resp
      end

      # return 401 still but with 'check email' body
      resp.status = 401
      @templates[:email_sent].populate resp, req
    end

    def handle_logout req, all
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
        resp.delete_cookie @keys[:cookie], { value: token }
      end

      # otherwise this thing will pretend like you're logging out even
      # if you were never logged in

      # we do when we actually process the token in the query string
      resp.status   = 303
      resp.location = (req_uri(req) +
        @targets[all ? :logout_one : :logout_all]).to_s

      resp
    end

    def handle_post req
      if logout = req.POST[@keys[:logout]]
        handle_logout req, logout
      elsif email = req.POST[@keys[:email]]
        handle_login req, email
      elsif token = req.cookies[@keys[:cookie]]
        # next check for a cookie
        handle_cookie req, token
      else
        default_401 req
      end
    end

    # @!endgroup

    # we want all these constants to be public so they show up in the docs
    DEFAULT_KEYS = { query: 'knock', cookie: 'lazyauth',
      email: 'email', logout: 'logout' }.freeze
    DEFAULT_VARS = { user: 'FCGI_USER', redirect: 'FCGI_REDIRECT'}.freeze
    DEFAULT_PATH = (Pathname(__FILE__) + '../../content').expand_path.freeze
    DEFAULT_EXP  = { url: TEN_MINUTES, cookie: TWO_WEEKS }.freeze

    SH = LazyAuth::Types::SymbolHash
    AT = LazyAuth::Types::ASCIIToken

    Keys = SH.schema(
      query:  AT.default('knock'.freeze),
      cookie: AT.default('lazyauth'.freeze),
      email:  AT.default('email'.freeze),
      logout: AT.default('logout'.freeze),
    ).hash_default

    Vars = SH.schema(
      user:     AT.default('FCGI_USER'.freeze),
      redirect: AT.default('FCGI_REDIRECT'.freeze),
    ).hash_default

    Expiry = SH.schema(
      url:    LazyAuth::Types::Duration.default(TEN_MINUTES),
      cookie: LazyAuth::Types::Duration.default(TWO_WEEKS),
    ).hash_default

    Mapping = SH.schema({
      default_401:      'basic-401.xhtml',
      default_409:      'basic-409.xhtml',
      default_500:      'basic-500.xhtml',
      knock_bad:        'basic-409.xhtml',
      knock_not_found:  'basic-409.xhtml',
      knock_expired:    'nonce-expired.xhtml',
      cookie_bad:       'basic-409.xhtml',
      cookie_not_found: 'basic-409.xhtml',
      cookie_expired:   'cookie-expired.xhtml',
      no_user:          'not-on-list.xhtml',
      email:            'email.xhtml',
      email_bad:        'email-409.xhtml',
      email_not_listed: 'not-on-list.xhtml',
      email_failed:     'basic-500.xhtml',
      email_sent:       'email-sent.xhtml',
    }.transform_values { |x| AT.default x.freeze }).hash_default

    # Templates = SH.schema(
    #   path: LazyAuth::Types::AbsolutePathname.default(DEFAULT_PATH),
    #   transform?: AT,
    #   mapping: Mapping,
    # ).hash_default

    RawTemplates = LazyAuth::Template::Mapper::RawParams.schema(
      mapping: Mapping
    ).hash_default

    Templates = LazyAuth::Types.Constructor(LazyAuth::Template::Mapper) do |x|
      raw  = RawTemplates.(x)
      path = raw.delete :path
      LazyAuth::Template::Mapper.new path, **raw
    end# .default do
    #   #raw  = RawTemplates.({})
    #   path = raw.delete :path
    #   LazyAuth::Template::Mapper.new path, **raw
    # end

    EMail = SH.schema(
      from: Dry::Types['string'],
      method: Dry::Types['symbol'].default(:sendmail),
      #options?: SH.map(Dry::Types['symbol'], LazyAuth::Types::Atomic)
    ).hash_default

    Config = SH.schema(
      state:      LazyAuth::State::Type,
      keys:       Keys,
      vars:       Vars,
      expiry:     Expiry,
      templates:  Templates,
      email:      EMail,
    ).hash_default

    # Config = Dry::Schema.Params do
    #   optional(:keys).hash do
    #     optional(:query).filled(LazyAuth::Types::ASCIIToken.default 'knock'.freeze)
    #     optional(:cookie).filled(LazyAuth::Types::ASCIIToken.default 'lazyauth'.freeze)
    #     required(:email).filled(LazyAuth::Types::ASCIIToken.default 'email'.freeze)
    #     required(:logout).filled(LazyAuth::Types::ASCIIToken.default 'logout'.freeze)
    #   end
    # end

    DEFAULTS = {
      keys: DEFAULT_KEYS,
      vars: DEFAULT_VARS,
      expiry: DEFAULT_EXP,
      templates: {
        path: DEFAULT_PATH,
        mapping: {
          default_401:      'basic-401.xhtml',
          default_409:      'basic-409.xhtml',
          default_500:      'basic-500.xhtml',
          knock_bad:        'basic-409.xhtml',
          knock_not_found:  'basic-409.xhtml',
          knock_expired:    'nonce-expired.xhtml',
          cookie_bad:       'basic-409.xhtml',
          cookie_not_found: 'basic-409.xhtml',
          cookie_expired:   'cookie-expired.xhtml',
          no_user:          'not-on-list.xhtml',
          email:            'email.xhtml',
          email_bad:        'email-409.xhtml',
          email_not_listed: 'not-on-list.xhtml',
          email_failed:     'basic-500.xhtml',
          email_sent:       'email-sent.xhtml',
        },
      },
      mail: {
        method: :sendmail,
      },
    }

    public

    def initialize state,
        keys: {}, vars: {}, expiry: {}, templates: {}, email: {}, debug: false

      @debug = debug

      # process config
      config = LazyAuth::Types::AppConfig.({
        state: state, keys: keys, vars: vars,
        expiry: expiry, templates: templates, mail: mail })
      # coerce config input and then deep merge with defaults
      config = DEFAULTS.deep_merge config

      # then assign members

      @keys = keys
      @vars = vars

      @templates = templates.is_a?(LazyAuth::Template::Mapper) ? templates :
        LazyAuth::Template::Mapper.new(path, templates[:mapping])
      @templates.verify! :email

      @state = State.new state, debug: debug
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
      #   resp.body << "LazyAuth::App only works as a FastCGI authorizer!"
      #   return resp.finish
      # end

      warn env.inspect if @debug

      begin
        resp = if knock = req.GET[@keys[:query]]
                 # check for a knock first; this overrides everything
                 handle_knock req, knock
               elsif req.post?
                 # next check for a login/logout attempt
                 handle_post req
               elsif token = req.cookies[@keys[:cookie]]
                 # next check for a cookie
                 handle_cookie req, token
               else
                 default_401 req
               end
      rescue LazyAuth::ErrorResponse => e
        resp = e.response
      end

      return resp.finish
    end
  end
end
