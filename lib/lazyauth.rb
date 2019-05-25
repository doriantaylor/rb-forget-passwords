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

    def make_nonce
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

    def nonce_ok? nonce
      [22, 26].include? nonce.length
      nonce =~ /^[A-Pa-p][0-9A-Za-z_-]+[A-Pa-p]$/
    end

    public

    def initialize dsn, query_key: 'knock', cookie_key: 'lazyauth',
        user_var: 'FCGI_USER', redirect_var: 'FCGI_REDIRECT'
      @state = State.new dsn
      warn @state.db.tables
      require 'logger'
      @state.db.loggers << Logger.new($stderr)
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
      if (knock = req.GET['knock'])
        # return 409 unless the knock parameter is valid
        unless nonce_ok? knock
          resp.status = 409
          resp.write 'boo hoo bad knock parameter'
          return resp.finish
        end

        # return 401 if the knock parameter doesn't pick a user

        # user = @state.match knock
        # unless user
        # end

        user = @state.user_for knock
        warn user

        # remove existing cookie
        if (nonce = req.cookies['lazyauth'])
          resp.delete_cookie 'lazyauth', { value: nonce }
        end

        target = uri_minus_query uri, 'knock'

        # set the user and redirect location as variables
        resp.set_header 'Variable-FCGI_USER', 'bob'
        resp.set_header 'Variable-FCGI_REDIRECT', target.to_s
        resp.set_cookie 'lazyauth', {
          value: make_nonce, expires: Time.at(2**31-1),
          secure: req.ssl?,  httponly: true,
        }

        # response has to be 200 or the auth handler won't pick it up
        # (response is already 200 by default)

        # content-length has to be present but empty or it will crap out
        resp.set_header 'Content-Length', ''

      elsif (nonce = req.cookies['lazyauth'])
        # return 409 unless the cookie is valid
        unless nonce_ok? nonce
          resp.status = 409
          resp.write 'boo hoo bad nonce'
          return resp.finish
        end

        # return 401 if the cookie doesn't pick a user
        user = @state.user_for nonce
        warn user

        # resp.write 'lol i see yer cookie'

        # just set the variable
        resp.set_header 'Variable-FCGI_USER', 'bob'
        
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
