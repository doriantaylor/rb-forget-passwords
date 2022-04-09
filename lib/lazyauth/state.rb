require_relative 'version'
require 'sequel'
require 'iso8601'
require 'uuidtools'
require 'uuid-ncname'
require 'uri'

module LazyAuth
  class State
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
          String   :principal, null: false, unique: true
          String   :email,     null: false, default: ''
          DateTime :added,     null: false, default: S::CURRENT_TIMESTAMP
          DateTime :disabled,  null: true
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


          m.dataset_module do
            where(:expired) { expires < S::CURRENT_TIMESTAMP }
            order :by_date, :added, :expires, :user

            def for id
              where(user: id)
            end

            def fresh cookie: false, oneoff: false
              base = where(slug: !cookie, oneoff: oneoff) {
                expires >= S::CURRENT_TIMESTAMP
              }

              base = base.left_join(Usage.latest, [:token]).where(seen: nil) if
                !cookie && oneoff

              base
            end

            def expire token
              uuid = UUID::NCName::from_ncname token, version: 1
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
          String   :token, null: false, fixed: true, size: 36
          String   :ip,    null: false, size: 40
          DateTime :seen,  null: false, default: S::CURRENT_TIMESTAMP
          primary_key [:token, :ip], name: :pk_usage
          foreign_key [:token], :token, name: :fk_usage_token
        },
      },
      acl: {
        class: :ACL,
        model: -> m {

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
              # then we try to get an exact match on the address
              if x = where(domain: d, address: email).first
                return x.ok
              else
                # then we try to get a match on the *address's* domain
                # (note we leave one segment)
                (0..mparts.length-1).each do |j|
                  md = mparts[j..mparts.length]
                  if y = where(domain: d, address: md).first
                    return y.ok
                  end
                end
              end
            end

            false
          end

          def m.permit domain, email, force: false
          end

          def m.revoke domain, email, force: false
          end

          def m.forget domain, email
          end

        },
        create: -> {
          String :domain, null: false, text: true, default: ''
          String :address, null: false, text: true
          TrueClass :ok, null: false, default: true
          DateTime :seen,  null: false, default: S::CURRENT_TIMESTAMP
          constraint(:domain_lc)  { domain  == trim(lower(domain)) }
          constraint(:address_lc) { address == trim(lower(address)) }
          constraint(:address_ne) { trim(address) != '' }
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
        m = db.method method
        m.call table, &proc
      end
    end

    def first_run force: false
      create_tables force: force

      me = self.class

      DISPATCH.each do |table, struct|
        cname = struct[:class]
        unless me.const_defined? cname
          # create the class
          cls = Class.new Sequel::Model(db[table])

          # bind the class name
          me.const_set cname, cls

          # set @whatever; i haven't decided if i want to dump these yet
          self.instance_variable_set "@#{table.to_s}".to_sym, cls

          # assemble the innards
          struct[:model].call cls
        end
      end

    end

    ONE_YEAR = ISO8601::Duration.new('P1Y').freeze

    public

    attr_reader :db, :user, :token, :usage, :acl

    def initialize dsn, create: true,
        query_expires: ONE_YEAR, cookie_expires: ONE_YEAR, debug: false
      @db = Sequel.connect dsn

      @expiry = { query: query_expires, cookie: cookie_expires }

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

    def id_for principal, create: false, email: nil
      ds  = @user.select(:id).where(principal: principal)
      row = ds.first

      if create
        if row
          row = @user[row.id]

          if email
            row.email = email
            row.save
          end

          return row.id
        else
          row = { principal: principal }
          row[:email] = email if email

          row = @user.new.set(row).save
        end
      end

      row.id if row
    end

    def new_user principal, email: ''
      @user
    end

    def new_token principal, cookie: false, oneoff: false, expires: nil
      id = principal.is_a?(Integer) ? principal : id_for(principal)
      raise "No user with ID #{principal} found" unless id

      # this should be a duration
      raise 'Expires should be an ISO8601::Duration' if
        expires && !expires.is_a?(ISO8601::Duration)
      expires ||= @expiry[cookie ? :cookie : :query]

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

    def expire_tokens_for principal, cookie: nil
      id = principal.is_a?(Integer) ? principal : id_for(principal)
      raise "No user with ID #{principal} found" unless id
      @token.for(id).expire_all cookie: cookie
    end

    def user_for token, cookie: false
      uuid  = UUID::NCName::from_ncname token, version: 1
      out  = @user.join(:token, user: :id).select(
        :principal, :expires).where(token: uuid, slug: !cookie).first
      if out
        out.principal
      end
    end

    def stamp_token token, ip, seen: DateTime.now
      uuid  = UUID::NCName::from_ncname token, version: 1
      raise "Could not get UUID from token #{token}" unless uuid
      @db.transaction do
        unless (row = @usage.where(token: uuid, ip: ip).first)
          @usage.insert(token: uuid, ip: ip, seen: seen)
        end
      end
    end
  end
end
