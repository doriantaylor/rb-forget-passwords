require 'nokogiri'
require 'xml-mixup'
require 'http-negotiate'

module LazyAuth

  class Template

    # XXX do we even need this?
    class Mapper

      private

      # XXX i can't remember what the nice way to get the gem root is lol
      DEFAULT_PATH = Pathname(__FILE__, '../../content').expand_path.freeze


      # Normalize the input to symbol `:like_this`.
      #
      # @param key [#to_s, #to_sym] the input to normalize
      #
      # @return [Symbol] the normalized key
      #
      def normalize key
        key.to_s.strip.downcase.gsub(/[[:space:]-]/, ?_).tr_s(?_, ?_).to_sym
      end

      public

      attr_reader :path, :base

      def initialize path = DEFAULT_PATH, base: nil, templates: {}
        @path      = Pathname(path).expand_path
        @base      = base
        @templates = templates.map do |k, v|
          name = normalize k
          template = v.is_a?(LazyAuth::Template) ? v :
            LazyAuth::Template.new(self, k, @path + v)
          [name, template]
        end.to_h
      end

      def [] key
        @templates[normalize key]
      end

      def manifest
        @templates.keys
      end

      # Ensure that the mapper contains templates with the given names.
      #
      # @param *names [Array<#to_s, #to_sym>] the template names
      #
      # @return [true, false]
      #
      def verify *names
        # i dunno, is there a better way to do this?
        (names.map { |k| normalize k } - manifest).empty?
      end

      # Ensure that the mapper contains templates with the given names
      # and raise an exception if it doesn't.
      #
      # @param *names [Array<#to_sym>] the template names
      #
      # @return [true, false]
      #
      def verify! *names
        verify(*names) or raise "Could not verify names: #{names.join ?,}"
      end
    end

    private

    TEXT_TEMPLATE = Nokogiri::XSLT.parse(
      (Pathname(__FILE__) + '../../etc/text-only.xsl').expand_path.slurp)

    # this is gonna be run in the context of the document
    TO_TEXT = -> {
      raise 'not implemented lol'
    }

    ATTRS = %w[
      about typeof rel rev property resource href src action data id class
    ].freeze

    ATTRS_XPATH = ('//*[%s]/@*' % ATTRS.map { |a| "@#{a}" }.join(?|)).freeze

    public

    attr_reader :name, :doc, :mapper

    def initialize mapper, name, content
      # boring members
      @mapper = mapper
      @name   = name

      # resolve content
      @doc = case content
             when Nokogiri::XML::Document then content
             when String, Pathname
               content = mapper.path + content
               fh = content.open
               Nokogiri.parse fh
             else
               raise ArgumentError, "Not sure what to do with #{content.class}"
             end
    end

    # Perform the variable substitution on the associated document and
    # return it.
    #
    # @param vars [#to_h] a hash-like object of variables.
    #
    # @return [Nokogiri::XML::Document] the altered document
    #
    def process vars = {}
      # sub all the placeholders for variables
      doc = @doc.dup

      # add doctype if missing

      # set the base URI
      if base = mapper.base
        # check for a <base href="..."/> already
        # otherwise check for a <title>, after which we'll plunk it
        # otherwise check for <head>, to which we will prepend
      end

      # do the processing instructions
      doc.xpath("/*//processing-instruction('var')").each do |pi|
      end

      # do the attributes
      doc.xpath(ATTRS_XPATH).each do |attr|
      end

      doc
    end

    # Given a document, perform rudimentary content negotiation.
    # Return the resulting string, or nil if no variant was chosen.
    #
    # @param doc [Nokogiri::XML::Document] the document
    # @param headers [#to_h] the header set for content negotiation
    # @param full [false, true] whether to return a content-header pair
    #
    # @return [String, Array<(String, String)>, nil] the serialized
    #  document (maybe, or maybe the Content-Type header too).
    #
    def serialize doc, headers = {}, full: false
      # XXX TODO go back and make it possible for this method to
      # return a hash with all the headers etc so i don't have to do
      # this dumb hack
      method = HTTP::Negotiate.negotiate(headers, {
        [:to_xml, 'application/xhtml+xml'] => {
          weight: 1.0, type: 'application/xhtml+xml' },
        [:to_html, 'text/html'] => { weight: 0.8, type: 'text/html' },
        [TO_TEXT, 'text/plain'] => { weight: 0.5, type: 'text/plain' },
      })

      # no type selected
      return unless method

      out = [doc.instance_exec(&method.first), method.last]

      full ? out : out.first
    end

    # Give us the Rack::Response object and we'll populate the headers
    # and body for you.
    #
    # @param resp [Rack::Response] the response to populate
    # @param headers [#to_h] the header set
    # @param vars [#to_h] the variable bindings
    #
    # @return [Rack::Response] the response object, updated in place
    #
    def populate resp, headers = {}, vars = {}
      if (resp.body, type = serialize(process(vars), headers, full: true))
        resp.content_type = type
        resp.length = resp.body.bytesize # not sure if necessary
      else
        # otherwise 406 lol, the client didn't like any of our responses
        resp.status = 406
      end

      resp
    end
  end
end
