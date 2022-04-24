require 'pathname'
require 'iso8601'
require 'uri'
require 'dry-schema'

module ForgetPasswords
  module Types
    include Dry::Types()

    private

    # ascii token
    ASCII = /^[A-Za-z_][0-9A-Za-z_.-]*$/

    # hostname
    HN = /^(?:[0-9a-z-]+(?:\.[0-9a-z-]+)*|[0-9a-f]{,4}(?::[0-9a-f]{,4}){,7})$/i

    public

    # XXX THIS IS A BAD SOLUTION TO THE URI PROBLEM
    Dry::Schema::PredicateInferrer::Compiler.infer_predicate_by_class_name false

    # config primitives

    ASCIIToken = Strict::String.constrained(format: ASCII).constructor(&:strip)

    # actually pretty sure i can define constraints for this type, oh well

    Hostname = String.constructor(&:strip).constrained(format: HN)

    Duration = Types.Constructor(ISO8601::Duration) do |x|
      begin
        out = ISO8601::Duration.new x.to_s.strip.upcase
      rescue ISO8601::Errors::UnknownPattern => e
        raise Dry::Types::CoercionError.new e
      end

      out
    end

    # okay so this shit doesn't seem to work (2022-04-12 huh? what doesn't?)

    # XXX note this is a fail in dry-types
    URI = Types.Constructor(::URI) do |x|
      begin
        out = ::URI.parse(x)
      rescue ::URI::InvalidURIError => e
        raise Dry::Types::CoercionError, e
      end

      out
    end

    RelativePathname = Types.Constructor(::Pathname) { |x| Pathname(x) }

    ExtantPathname = Types.Constructor(::Pathname) do |x|
      out = Pathname(x).expand_path
      dir = out.dirname
      raise Dry::Types::CoercionError, "#{dir} does not exist" unless
        out.exist? || dir.exist?

      out
    end


    # should be WritablePathname but whatever
    WritablePathname = Types.Constructor(::Pathname) do |x|
      out = Pathname(x)
      dir = out.expand_path.dirname
      raise Dry::Types::CoercionError, "#{dir} is not writable" unless
        dir.writable?
      raise Dry::Types::CoercionError, "#{out} can't be overwritten" if
        out.exist? and !out.writable?
      out
    end

    NormSym = Symbol.constructor do |k|
      k.to_s.strip.downcase.tr_s(' _-', ?_).to_sym
    end

    # symbol hash
    SymbolHash = Hash.schema({}).with_key_transform do |k|
      NormSym.call k
    end

    # apparently you can't go from schema to map
    SymbolMap = Hash.map NormSym, Any

    # this is a generic type for stuff that comes off the command line
    # or out of a config file that we don't want to explicitly define
    # but nevertheless needs to be coerced (in particular integers,
    # floats) so it can be passed into eg a constructor
    Atomic = Coercible::Integer | Coercible::Float | Coercible::String
  end

end

module Dry::Types::Builder
  def hash_default
    # obtain all the required keys from the spec
    reqd = keys.select(&:required?)

    if reqd.empty?
      # there aren't any requireed keys, but we'll set the empty hash
      # as a default if there exist optional keys, otherwise any
      # default will interfere with input from upstream.
      return default({}.freeze) unless keys.empty?
    else
      # similarly, we only set a default if all the required keys have them.
      return default(reqd.map { |k| [k.name, k.value] }.to_h.freeze) if
        reqd.all?(&:default?)
      # XXX THIS WILL FAIL IF THE DEFAULT IS A PROC; THE FAIL IS IN DRY-RB
    end

    # otherwise just return self
    self
  end
end
