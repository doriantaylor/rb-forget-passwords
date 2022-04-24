# XXX THIS IS A HACK MFERS
require 'rack/handler'
require 'rack/handler/fastcgi'

module ForgetPasswords
  # XXX this unfortunate chunk of code exists because of
  # https://bz.apache.org/bugzilla/show_bug.cgi?id=65984
  class FastCGI < Rack::Handler::FastCGI

    def self.send_headers(out, status, headers)
      out.print "Status: #{status}\r\n"
      headers.each do |k, vs|
        vs.split("\n").each { |v|  out.print "#{k}: #{v}\r\n" }
      end
      out.print "\r\n"
      # we remove out.flush from the headers
      # out.flush
    end

    def self.send_body(out, body)
      body.each { |part| out.print part }
      # this one we keep and put it outside the loop
      out.flush
    end
  end

  Rack::Handler.register 'hacked-fcgi', FastCGI
end
