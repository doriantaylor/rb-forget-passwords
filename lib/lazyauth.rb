require 'lazyauth/version'
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

    def uri_minus uri, *key
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

    def initialize
    end

    def call env
      req  = Rack::Request.new env
      uri  = URI(req.base_url) + env['REQUEST_URI']
      resp = Rack::Response.new

      # unless env['FCGI_ROLE'] == 'AUTHENTICATOR'
      #   resp.status = 500
      #   resp.body << "LazyAuth::App only works as a FastCGI authenticator!"
      #   return resp.finish
      # end

      # obtain the query string
      if (knock = req.GET['knock'])
        # return 409 unless the knock parameter is valid
        unless nonce_ok? knock
          resp.status = 409
          resp.body << 'boo hoo bad knock parameter'
          return resp.finish
        end

        # return 401 if the knock parameter doesn't pick a user

        # user = @state.match knock
        # unless user
        # end

        target = uri_minus uri, 'knock'

        # set the cookie and the variable
        resp.set_header 'Variable-USER', 'bob'
        resp.set_header 'Variable-Location', target.to_s
        resp.set_cookie 'lazyauth',
          { value: make_nonce, expires: Time.at(2**31-1) }
        resp.status = 200
        resp.location = target.to_s
        resp.body << 'lol setcher cookie ' + uri.to_s
      elsif (nonce = req.cookies['lazyauth'])
        # return 409 unless the cookie is valid
        unless nonce_ok? knock
          resp.status = 409
          resp.body << 'boo hoo bad nonce'
          return resp.finish
        end

        # return 401 if the cookie doesn't pick a user

        resp.body << 'lol i see yer cookie'

        # just set the variable
        resp.set_header 'Variable-USER', 'bob'
      else
        # return 401
        resp.status = 401
        resp.body << 'boo hoo'
      end

      resp.finish
    end
  end
end
