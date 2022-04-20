require_relative 'version'
require 'sequel'
require 'iso8601'
require 'uuidtools'
require 'uuid-ncname'
require 'uri'

require 'lazyauth/types'

module LazyAuth
  class State

    TEN_MINUTES = ISO8601::Duration.new('PT10M').freeze
    TWO_WEEKS   = ISO8601::Duration.new('P2W').freeze

    Expiry = LazyAuth::Types::SymbolHash.schema(
      url:    LazyAuth::Types::Duration.default(TEN_MINUTES),
      cookie: LazyAuth::Types::Duration.default(TWO_WEEKS)).hash_default

    RawParams = LazyAuth::Types::SymbolHash.schema(
      dsn:       LazyAuth::Types::String,
      user?:     LazyAuth::Types::String,
      password?: LazyAuth::Types::String,
      expiry:    Expiry).hash_default

    Type = LazyAuth::Types.Constructor(self) do |x|
      # this will w
      if x.is_a? self
        x
      else
        raw = RawParams.(x)
        self.new raw[:dsn], **raw.slice(:user, :password)
      end
    end

    private

    S = Sequel

    DISPATCH = {
      # key is table name
      user: {
        # model class name if wildly different from table name
        class: :User,

        # these are the model bits
        model: -> m {
          m.one_to_many :token, key: :user, class: :Token
        },

        # this is the schema object
        create: -> {
          # need to write it this way if you want the pk to auto-increment
          primary_key :id, type: Integer, primary_key_constraint_name: :pk_user
          String   :principal, null: false, text: true, unique: true
          String   :email,     null: false, text: true, unique: true
          DateTime :added,     null: false, default: S::CURRENT_TIMESTAMP
          DateTime :disabled,  null: true
          constraint :ck_principal, principal: S.function(:trim, :principal)
          constraint(:ck_principal_ne) {
            S.function(:length, S.function(:trim, :principal)) > 0 }
          constraint :ck_email,
          email: S.function(:trim, S.function(:lower, :email))
          constraint(:ck_email_at) { S.like(:email, '%_@_%') }
        },
      },
      token: {
        class: :Token,
        model: -> m {
          m.one_to_many :usage, key: :token
          m.many_to_one :user

          # we can use exclude to invert this
          def m.expired date: S::CURRENT_TIMESTAMP
            where { expires < date }
          end

          def m.valid? token, cookie: false, oneoff: nil
            uuid = UUID::NCName.valid?(token) ?
              UUID::NCName.from_ncname(token) : token
            !!where(token: uuid).fresh(cookie: cookie, oneoff: oneoff).first
          end

          m.dataset_module do
            where(:expired) { expires < S::CURRENT_TIMESTAMP }
            order :by_date, :added, :expires, :user

            def for id
              where(user: id)
            end

            def id_for token
              uuid = UUID::NCName.valid?(token) ?
                UUID::NCName.from_ncname(token) : token

              rec = where(token: uuid).first
              rec.user if rec
            end

            def fresh cookie: false, oneoff: nil
              w = { slug: !cookie }
              w[:oneoff] = !!oneoff unless oneoff.nil?
              base = where(**w) { expires > S::CURRENT_TIMESTAMP }

              base = base.left_join(Usage.latest, [:token]).where(seen: nil) if
                !cookie && oneoff

              base
            end

            def expire token
              uuid = UUID::NCName.valid?(token) ?
                UUID::NCName.from_ncname(token) : token

              where(token: uuid).update(expires: S::CURRENT_TIMESTAMP)
            end

            def expire_all cookie: nil
              base = where { expires > S::CURRENT_TIMESTAMP }
              base = base.where(slug: !cookie) unless cookie.nil?

              base.update(expires: S::CURRENT_TIMESTAMP)
            end
          end
        },
        create: -> {
          String    :token,   null: false, fixed: true, size: 36
          Integer   :user,    null: false
          TrueClass :slug,    null: false, default: false
          TrueClass :oneoff,  null: false, default: false
          DateTime  :added,   null: false, default: S::CURRENT_TIMESTAMP
          DateTime  :expires, null: false, default: Time.at(2**31-1).to_datetime
          primary_key [:token], name: :pk_token
          unique [:token, :user], name: :uk_token
          foreign_key [:user], :user,  key: :id, name: :fk_token_user
          constraint :ck_token,
          :token => S.function(:trim, S.function(:lower, :token))
        },
      },
      usage: {
        class: :Usage,
        model: -> m {
          m.many_to_one :token

          db = m.db

          LATEST = db.from{usage.as(:ul)}.exclude(
            db.from{usage.as(:ur)}.where{
              (ul[:seen] < ur[:seen]) & {ul[:token] => ur[:token]}
            }.select(1).exists)

          # don't forget it's *def m.whatever*
          def m.latest
            LATEST
          end

        },
        create: -> {
          String   :token,   null: false, fixed: true, size: 36
          String   :ip,      null: false, size: 40
          DateTime :created, null: false, default: S::CURRENT_TIMESTAMP
          DateTime :seen,    null: false, default: S::CURRENT_TIMESTAMP
          primary_key [:token, :ip], name: :pk_usage
          foreign_key [:token], :token, name: :fk_usage_token
        },
      },
      acl: {
        class: :ACL,
        model: -> m {

          # XXX TAKE INTO ACCOUNT user.disabled

          def m.listed? domain, email
            # normalize the inputs
            domain = (
              domain.respond_to?(:host) ? domain.host : domain).strip.downcase
            email = email.to_s.strip.downcase
            _, mx = email.split ?@, 2
            mparts = mx.split ?.

            # we start from the most specific domain from the request-uri
            dparts = domain.split ?.
            (0..dparts.length).each do |i|
              d = dparts[i..dparts.length].join ?.
              # warn "trying #{email} on #{d}"

              # then we try to get an exact match on the address
              if x = where(domain: d, address: email).first
                return x.ok
              else
                # then we try to get a match on the *address's* domain
                # (note we leave one segment)
                (0..mparts.length-1).each do |j|
                  md = mparts[j..mparts.length].join ?.
                  # warn "trying #{md} on #{d}"
                  if y = where(domain: d, address: md).first
                    return y.ok
                  end
                end
              end
            end

            false
          end

          def m.permit domain, email, force: false
            # insert or update
            domain = (
              domain.respond_to?(:host) ? domain.host : domain
            ).to_s.strip.downcase
            email = email.to_s.strip.downcase
            # warn "domain: #{domain}, email: #{email}"
            rows = where(domain: domain, address: email).update ok: true
            # warn rows.inspect
            return true if rows > 0
            insert domain: domain, address: email
            true
          end

          def m.revoke domain, email, force: false
            # update, noop if not present?
            domain = (
              domain.respond_to?(:host) ? domain.host : domain
            ).to_s.strip.downcase
            email = email.to_s.strip.downcase
            rows = where(domain: domain, address: email).update ok: false
            rows > 0 # if this is true then the record was updated
          end

          def m.forget domain, email
            domain = (
              domain.respond_to?(:host) ? domain.host : domain).strip.downcase
            email = email.to_s.strip.downcase
            rows = where(domain: domain, address: email).delete
            rows > 0
          end

        },
        create: -> {
          String :domain, null: false, text: true, default: ''
          String :address, null: false, text: true
          TrueClass :ok, null: false, default: true
          DateTime :seen,  null: false, default: S::CURRENT_TIMESTAMP
          constraint :ck_domain,
          domain: S.function(:trim, S.function(:lower, :domain))
          constraint :ck_address,
          address: S.function(:trim, S.function(:lower, :address))
          constraint(:ck_address_ne) {
            S.function(:length, S.function(:trim, :address)) > 0 }
        },
      },
    }

    # XXX this constant is arguably not necessary but ehh
    CREATE_SEQ = DISPATCH.keys.freeze

    def create_tables force: false

      # lol sneaky
      method = 'create_table' + (force ? ?! : ??)

      # arggh sqlite has no drop table cascade and sequel doesn't
      # compensate for it

      cascade = force && db.adapter_scheme != :sqlite

      CREATE_SEQ.each do |table|
        # snag the proc
        proc = DISPATCH[table][:create]
        # sequel has no drop cascade for sqlite and this is on purpose
        db.drop_table table, cascade: true if
          cascade && db.table_exists?(table)
        # m = db.method method
        # m.call table, &proc
        # warn table
        db.send method, table, &proc
      end
    end

    def first_run force: false
      create_tables force: force

      me = self.class

      DISPATCH.each do |table, struct|
        cname = struct[:class]
        if me.const_defined? cname
          cls = me.const_get cname
        else
          # create the class
          cls = Class.new Sequel::Model(db[table])

          # bind the class name
          me.const_set cname, cls

          # assemble the innards
          struct[:model].call cls
        end

        # set @whatever; i haven't decided if i want to dump these yet
        var = "@#{table.to_s}".to_sym
        self.instance_variable_set(var, cls) unless
          instance_variable_defined? var
      end

    end

    ONE_YEAR = ISO8601::Duration.new('P1Y').freeze

    public

    attr_reader :db, :expiry, :user, :token, :usage, :acl

    def initialize dsn, create: true, user: nil, password: nil,
        expiry: { query: TEN_MINUTES, cookie: TWO_WEEKS }, debug: false
      @db = Sequel.connect dsn

      @expiry = Expiry.(expiry)
      # warn expiry.inspect

      if debug
        require 'logger'
        @db.loggers << Logger.new($stderr)
      end

      first_run if create
    end

    def initialized?
      CREATE_SEQ.select { |t| db.table_exists? t } == CREATE_SEQ
    end

    def initialize!
      first_run force: true
    end

    def transaction &block
      @db.transaction(&block)
    end

    # XXX 2022-04-10 the email address is canonical now, lol

    def record_for principal, create: false, email: nil
      # so we can keep the same interface
      if principal
        # ensure this is a stripped string
        principal = principal.to_s.strip
        raise ArgumentError,
          'principal cannot be an empty string' if principal.empty?
      else
        raise ArgumentError,
          'email must be defined if principal is not' unless email
        # note we don't normalize case for the principal (may be dumb tbh)
        principal = email.to_s.strip
      end

      ds  = @user.select(:id).where(principal: principal)
      row = ds.first

      if create
        if email
          email = email.to_s.strip.downcase
          raise ArgumentError,
            "email must be a valid address, not #{email}" unless
            email.include? ?@
        elsif principal.include? ?@
          email = principal.dup
        else
          raise ArgumentError,
            'principal must be an email address if another not supplied'
        end

        if row
          row = @user[row.id]
          row.email = email
          row.save
        else
          row = { principal: principal, email: email  }
          row = @user.new.set(row).save
        end
      end

      row
    end

    def id_for principal, create: true, email: nil
      user = record_for principal, create: create, email: email
      user.id if user
    end

    def new_user principal, email: nil
      record_for principal, create: true, email: email
    end

    def new_token principal, cookie: false, oneoff: false, expires: nil
      id = principal.is_a?(Integer) ? principal : id_for(principal)
      raise "No user with ID #{principal} found" unless id

      # this should be a duration
      raise 'Expires should be an ISO8601::Duration' if
        expires && !expires.is_a?(ISO8601::Duration)
      expires ||= @expiry[cookie ? :cookie : :url]

      oneoff = false if cookie

      now = DateTime.now
      # the iso8601 guy didn't make it so you could add a duration to
      # a DateTime, even though ISO8601::DateTime embeds a DateTime.
      # noOOoOOOo that would be too easy; instead you have to reparse it.
      expires = now +
        (expires.to_seconds(ISO8601::DateTime.new now.iso8601) / 86400.0)
      # anyway an integer to DateTime is a day, so we divide.

      uuid = UUIDTools::UUID.random_create

      @token.insert(user: id, token: uuid.to_s, slug: !cookie,
        oneoff: !!oneoff, expires: expires)

      UUID::NCName::to_ncname uuid, version: 1
    end

    # from the author of sequel (2019-05-27):
    #
    # 15:11 < jeremyevans> dorian:
    # DB.from{same_table.as(:a)}.exclude(
    #   DB.from{same_table.as(:b)}.where{(a[:order] < b[:order]) &
    #     {a[:key]=>b[:key]}}.select(1).exists)

    def token_for principal, cookie: false, oneoff: false, expires: nil
      id = principal.is_a?(Integer) ? principal : id_for(principal)
      raise "No user with ID #{principal} found" unless id

      # only query strings can be oneoffs
      cookie = !!cookie
      oneoff = false if cookie
      oneoff = !!oneoff

      # obtain the last (newest) "fresh" token for this user
      row = @token.fresh(cookie: cookie, oneoff: oneoff).for(id).by_date.first
      return UUID::NCName::to_ncname row.token, version: 1 if row
    end



    # Expire all cookies associated with a principal.
    #
    # @param
    # @param
    #
    # @return
    #
    def expire_tokens_for principal, cookie: nil
      id = principal.is_a?(Integer) ? principal : id_for(principal)
      raise "No user with ID #{principal} found" unless id
      @token.for(id).expire_all cookie: cookie
    end

    # Retrieve the user associated with a token, whether nonce or cookie.
    #
    # @param token [String] the token
    # @param id [false, true] the user ID instead of the principal
    # @param cookie [false, true] whether the token is a cookie
    #
    # @return [String, nil] the user principal identifier or nil
    #
    def user_for token, record: false, id: false, cookie: false
      uuid = UUID::NCName::from_ncname token, version: 1
      out  = @user.where(disabled: nil).join(:token, user: :id).select(
        :id, :principal, :email, :expires
      ).where(token: uuid, slug: !cookie).first

      # return the whole record if asked for it otherwise the id or principal
      record ? out : id ? out.id : out.principal if out
    end

    # Freshen the expiry date of the token.
    #
    # @param token [String] the token
    # @param from [Time, DateTime] the reference time
    # @param cookie [true,false] whether the token is a cookie
    #
    # @return [true, false] whether any tokens were affected.
    #
    def freshen_token token, from: Time.now, cookie: true
      uuid = UUID::NCName.valid?(token) ?
        UUID::NCName.from_ncname(token) : token
      exp = @expiry[cookie ? :cookie : :query]
      # this is dumb that this is how you have to do this
      delta = from.to_time + exp.to_seconds(ISO8601::DateTime.new from.iso8601)
      # aaanyway...
      rows = @token.where(
        token: uuid).fresh(cookie: cookie).update(expires: delta)
      rows > 0
    end

    # Add a token to the usage log and associate it with an
    # IP address.
    #
    # @param token [String] the token
    # @param ip [String] the IP address that used
    # @param seen [Time,DateTime] The timestamp (defaults to now).
    #
    # @return [LazyAuth::State::Usage] the token's usage record
    #
    def stamp_token token, ip, seen: DateTime.now
      uuid  = UUID::NCName::from_ncname token, version: 1
      raise "Could not get UUID from token #{token}" unless uuid
      @db.transaction do
        warn @usage.where(token: uuid, ip: ip).inspect
        rec = @usage.where(token: uuid, ip: ip).first
        warn "#{uuid} #{ip}"
        if rec
          rec.update(seen: seen)
          rec # yo does update return the record? or
        else
          @usage.insert(token: uuid, ip: ip, seen: seen)
        end
      end
    end
  end
end
