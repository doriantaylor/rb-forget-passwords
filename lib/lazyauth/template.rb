require 'http/negotiate'

module LazyAuth
  
  class Template

    # XXX do we even need this?
    # class Map
    #
    #   def register template
    #   end
    # end

    def initialize name, content
    end

    # this will just return
    def process vars, headers = nil
    end

    # give us the Rack::Response object and we'll populate the headers
    # and body for you
    def send_response resp, vars, headers = nil
    end
  end
end
