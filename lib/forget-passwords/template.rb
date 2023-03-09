require 'nokogiri'
require 'stringio'
require 'xml-mixup'
require 'http-negotiate'
require 'forget-passwords/types'
require 'uri'
require 'time'

module ForgetPasswords

  class Template

    # XXX do we even need this?
    class Mapper

      private

      # XXX i can't remember what the nice way to get the gem root is lol
      DEFAULT_PATH = (
        Pathname(__FILE__).parent + '../../content').expand_path.freeze

      # this is a default document root subpath
      DEFAULT_DOCROOT = '.forgetpw'.freeze

      # Normalize the input to symbol `:like_this`.
      #
      # @param key [#to_s, #to_sym] the input to normalize
      #
      # @return [Symbol] the normalized key
      #
      def normalize key
        key.to_s.strip.downcase.gsub(/[[:space:]-]/, ?_).tr_s(?_, ?_).to_sym
      end

      TType = ForgetPasswords::Types.Instance(ForgetPasswords::Template)

      THash = ForgetPasswords::Types::Hash.map(ForgetPasswords::Types::NormSym,
        ForgetPasswords::Types::String).default({}.freeze)

      RawParams = ForgetPasswords::Types::SymbolHash.schema(
        path:       ForgetPasswords::Types::ExtantPathname.default(DEFAULT_PATH),
        mapping:    THash,
        base?:      ForgetPasswords::Types::URI,
        transform?: ForgetPasswords::Types::URI,
      ).hash_default

      public

      Type = ForgetPasswords::Types.Constructor(self) do |input|
        # what we're gonna do is validate the input as a hash, then use it
        input = RawParams.(input)
        path = input.delete :path
        self.new(path, **input)
      end

      attr_reader :path, :base, :transform

      def initialize path = DEFAULT_PATH, base: nil,
          transform: nil, mapping: {}
        @path      = Pathname(path).expand_path
        @base      = base
        @transform = transform
        @mapping   = mapping
        @templates = {
          @path => mapping.map do |k, v|
            name = normalize k
            template = v.is_a?(ForgetPasswords::Template) ? v :
              ForgetPasswords::Template.new(self, k, @path + v)
            [name, template]
          end.to_h
        }
      end

      # Fetch the appropriate template, optionally relative to a given root.
      #
      # @param key [Symbol, #to_sym] the template key.
      # @param root [nil, String] an optional document root.
      #
      # @return [nil, ForgetPasswords::Template] a template
      #
      def [] key, root = nil
        key = normalize key
        # bail early if we don't know the key
        return unless @mapping[key]

        # obtain optional root
        root = if root
                 r = root.respond_to?(:env) ? root.env['DOCUMENT_ROOT'] : root
                 r = (Pathname(r) + DEFAULT_DOCROOT).expand_path
                 r.readable? ? r : nil
               end

        if root
          # get the full file path
          fp = root + @mapping[key]
          if fp.readable?
            mt       = fp.mtime
            rootmap  = @templates[root] ||= {}
            template = rootmap[key]

            # congratulations, you found it
            return template if template and mt <= template.modified

            # XXX this could explode obvs
            begin
              template = ForgetPasswords::Template.new(self, key, fp, mt)
              rootmap[key] = template
              return template
            rescue
              # XXX duhh what do we do here
              nil
            end
          end
        end

        # otherwise just return the default
        @templates[@path][key]
      end

      def []= key, path
        name = normalize key
        # XXX do something less dumb here
        @templates[@path][name] = path.is_a?(ForgetPasswords::Template) ? path :
          ForgetPasswords::Template.new(self, key, @path + path)
      end

      def manifest
        @mapping.keys
      end

      # Ensure that the mapper contains templates with the given names.
      #
      # @param *names [Array<#to_s, #to_sym>] the template names
      #
      # @return [true, false]
      #
      def verify *names
        names = names.first if names.first.is_a? Array
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

    include XML::Mixup

    private

    TEXT_TEMPLATE = Nokogiri::XSLT.parse(
      (Mapper::DEFAULT_PATH + '../etc/text-only.xsl').expand_path.read)

    # this is gonna be run in the context of the document
    TO_XML  = -> { to_xml }
    TO_HTML = -> { to_html }
    TO_TEXT = -> {
      TEXT_TEMPLATE.apply_to(self).to_s
    }

    ATTRS = %w[
      about typeof rel rev property resource href src
      action data id class name value
    ].freeze

    ATTRS_XPATH = ('//*[%s]/@*' % ATTRS.map { |a| "@#{a}" }.join(?|)).freeze

    XPATHNS = {
      html: 'http://www.w3.org/1999/xhtml',
      svg:  'http://www.w3.org/2000/svg',
      xsl:  'http://www.w3.org/1999/XSL/Transform',
    }.freeze

    public

    attr_reader :name, :doc, :mapper, :modified

    def initialize mapper, name, content, modified = Time.now
      # boring members
      @mapper   = mapper
      @name     = name
      @modified = modified

      # resolve content
      @doc = case content
             when Nokogiri::XML::Document then content
             when IO, Pathname
               content = mapper.path + content
               fh = content.respond_to?(:open) ? content.open : content
               Nokogiri::XML.parse fh
             when String
               Nokogiri::XML.parse content
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
    def process vars: {}, base: nil, transform: nil
      # sub all the placeholders for variables
      doc = @doc.dup

      # add doctype if missing
      doc.create_internal_subset('html', nil, nil) unless doc.internal_subset

      # set the base URI
      if base ||= mapper.base
        if b = doc.at_xpath('(/html:html/html:head/html:base)[1]', XPATHNS)
          # check for a <base href="..."/> already
          b['href'] = base.to_s
        elsif t = doc.at_xpath('(/html:html/html:head/html:title)[1]', XPATHNS)
          # otherwise check for a <title>, after which we'll plunk it
          markup spec: { nil => :base, href: base.to_s }, after: t
        elsif h = doc.at_xpath('/html:html/html:head[1]', XPATHNS)
          # otherwise check for <head>, to which we will prepend
          markup spec: { nil => :base, href: base.to_s }, parent: h
        end
      end

      # add xsl transform if present
      if transform ||= mapper.transform
        pi = { '#pi' => 'xml-stylesheet',
            type: 'text/xsl', href: transform.to_s }
        if t = doc.at_xpath("/processing-instruction('xml-stylesheet')[1]")
          t = markup spec: pi, replace: t
        else
          t = markup spec: pi, before: doc.children.first
        end
      end

      # do the processing instructions
      doc.xpath("/*//processing-instruction('var')").each do |pi|
        key = pi.content.delete_prefix(?$).delete_suffix(??).to_sym
        if vars[key]
          text = pi.document.create_text_node vars[key].to_s
          pi.replace text
        end
      end

      # do the attributes
      doc.xpath(ATTRS_XPATH).each do |attr|
        attr.content = attr.content.gsub(/\$([A-Z_][0-9A-Z_]*)/) do |key|
          key = key.delete_prefix ?$
          vars[key.to_sym] || "$#{key}"
        end
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
      method, type = HTTP::Negotiate.negotiate(headers, {
        [TO_XML, 'application/xhtml+xml'] => {
          weight: 1.0, type: 'application/xhtml+xml' },
        [TO_HTML, 'text/html'] => { weight: 0.8, type: 'text/html' },
        [TO_TEXT, 'text/plain'] => { weight: 0.5, type: 'text/plain' },
      })

      # no type selected
      return unless method

      # warn method.inspect

      out = [doc.instance_exec(&method), type]

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
    def populate resp, headers = {}, vars = {}, base: nil

      if (body, type = serialize(
        process(vars: vars, base: base), headers, full: true))
        #resp.length = body.bytesize # not sure if necessary
        resp.write body
        resp.content_type = type
      else
        # otherwise 406 lol, the client didn't like any of our responses
        resp.status = 406
      end

      resp
    end
  end
end
