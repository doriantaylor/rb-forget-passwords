require_relative 'version'
require 'sequel'
require 'iso8601'
require 'uuidtools'
require 'uuid-ncname'

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
          m.dataset_module do
            def hurr
            end
          end
        },
        create: -> {
          String   :token, null: false, unique: true, fixed: true, size: 36
          String   :ip,    null: false, size: 40
          DateTime :seen,  null: false, default: S::CURRENT_TIMESTAMP
          primary_key [:token, :ip], name: :pk_usage
          foreign_key [:token], :token, name: :fk_usage_token
        },
      },
    }

    CREATE_SEQ = %w(user token usage).map(&:to_sym).freeze

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
        warn m
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

    attr_reader :db, :user, :token, :usage

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

    def transaction
      yield @db.transaction 
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
      expires ||= @expiry[cookie ? :cookie : :query]

      now = DateTime.now
      # the iso8601 guy didn't make it so you could add a duration to
      # a DateTime, even though ISO8601::DateTime embeds a DateTime.
      # noOOoOOOo that would be too easy; instead you have to reparse it.
      expires = now +
        (expires.to_seconds(ISO8601::DateTime.new now.iso8601) / 86400.0)
      # anyway an integer to DateTime is a day, so we divide.
      
      uuid = UUIDTools::UUID.random_create

      @token.insert(user: id, token: uuid.to_s, slug: !cookie, expires: expires)

      UUID::NCName::to_ncname uuid, version: 1
    end

# from the author of sequel (2019-05-27):
#
# 15:11 < jeremyevans> dorian:
# DB.from{same_table.as(:a)}.exclude(DB.from{same_table.as(:b)}.where{(a[:order]
#                     < b[:order]) & {a[:key]=>b[:key]}}.select(1).exists)


    def token_for principal, cookie: false, oneoff: false, expires: nil
      id = principal.is_a?(Integer) ? principal : id_for(principal)
      raise "No user with ID #{principal} found" unless id

      # only query strings can be oneoffs
      oneoff = false if cookie

      # obtain the token tat 

      warn @db[:usage].exclude(db[:usage].select(1).where(token: S[:u][:token])).as(:u).inspect

      # nx = @db[:usage].from(S[:usage].as(:u)).exclude(
      #   @db[:usage].select(1).where(token: S[:u][:token]) {
      #     seen < S[:u][:seen] }.exists)

      # warn nx.join

      # warn nx

      #nx = @usage.select(1).where { Sequel[:seen] < 

      #@token.join(:usage, :user) @usage.

      #ds = @token.select(:token).where(slug: !cookie)
    end

    def user_for token, cookie: false
      uuid  = UUID::NCName::from_ncname token, version: 1
      out   = @token.join(:user).select(S[:user][:principal], :expires).
        where(token: uuid, slug: !cookie)
      if out.first
        out.first.principal
      end
    end

    def stamp_token token, ip, when: DateTime.now
    end
  end
end
