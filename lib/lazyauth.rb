require 'lazyauth/version'
require 'lazyauth/state'
require 'uuid-ncname'

module LazyAuth
  class Middleware
  end

  class App
    require 'time'
    require 'uri'
    require 'rack/request'
    require 'rack/response'

    require 'uuidtools'
    require 'uuid-ncname'

    private

    def make_token
      UUID::NCName.to_ncname UUIDTools::UUID.random_create, version: 1
    end

    def uri_minus_query uri, *key
      return uri unless uri.query
      uri = uri.dup
      key = key.map { |k| k.to_s }

      query = URI.decode_www_form(uri.query).reject do |pair|
        key.include? pair.first
      end
      uri.query = query.empty? ? nil : URI.encode_www_form(query)
      uri
    end

    def token_ok? token
      [22, 26].include? token.length
      token =~ /^[A-Pa-p][0-9A-Za-z_-]+[A-Pa-p]$/
    end

    TWO_WEEKS = ISO8601::Duration.new('P2W').freeze

    public

    attr_reader :query_key, :cookie_key, :user_var, :redirect_var

    def initialize dsn, query_key: 'knock', cookie_key: 'lazyauth',
        user_var: 'FCGI_USER', redirect_var: 'FCGI_REDIRECT',
        expires: TWO_WEEKS, debug: false

      @query_key    = query_key
      @cookie_key   = cookie_key
      @user_var     = user_var
      @redirect_var = redirect_var

      @state = State.new dsn, debug: debug
      # if debug
      #   warn @state.db.tables
      #   require 'logger'
      #   @state.db.loggers << Logger.new($stderr)
      # end
    end

    def call env
      req  = Rack::Request.new env
      uri  = URI(req.base_url) + env['REQUEST_URI']
      resp = Rack::Response.new

      # unless env['FCGI_ROLE'] == 'AUTHORIZER'
      #   resp.status = 500
      #   resp.body << "LazyAuth::App only works as a FastCGI authorizer!"
      #   return resp.finish
      # end

      # obtain the query string
      if (knock = req.GET[query_key])
        # return 409 unless the knock parameter is valid
        unless token_ok? knock
          resp.status = 409
          resp.write 'boo hoo bad knock parameter'
          return resp.finish
        end

        # return 401 if the knock parameter doesn't pick a user

        # user = @state.match knock
        # unless user
        # end

        user = @state.user_for knock
        unless user
          resp.status = 401
          resp.write "Could not find a user for token #{knock}."
          return resp.finish
        end

        @state.stamp_token knock, req.ip

        # remove existing cookie
        if (token = req.cookies[cookie_key])
          @state.token.expire token
          resp.delete_cookie cookie_key, { value: token }
        end

        target = uri_minus_query uri, query_key

        token = @state.new_token user, cookie: true

        # set the user and redirect location as variables
        resp.set_header "Variable-#{user_var}", 'bob'
        resp.set_header "Variable-#{redirect_var}", target.to_s
        resp.set_cookie cookie_key, {
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

        # return 401 if the cookie doesn't pick a user
        user = @state.user_for token, cookie: true
        unless user
          resp.status = 401
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
        resp.write 'boo hoo'
      end

      resp.finish
    end
  end
end
