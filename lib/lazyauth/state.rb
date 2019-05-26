require_relative 'version'
require 'sequel'
module LazyAuth
  class State
    private

    S = Sequel

    def create_tables force: false
      # XXX wrap these in a thing

      # lol sneaky
      method = 'create_table' + (force ? ?! : ??)

      db.send method, :user do
        # need to do this if you want to auto increment
        primary_key :id, type: Integer, primary_key_constraint_name: :pk_user
        String   :principal, null: false, unique: true
        String   :email,     null: false, default: ''
        DateTime :added,     null: false, default: S::CURRENT_TIMESTAMP
        DateTime :disabled,  null: true
      end

      db.send method, :token do
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
      end

      db.send method, :usage do
        String   :token, null: false, unique: true, fixed: true, size: 36
        String   :ip,    null: false, size: 40
        DateTime :seen,  null: false, default: S::CURRENT_TIMESTAMP
        primary_key [:token, :ip], name: :pk_usage
        foreign_key [:token], :token, name: :fk_usage_token
      end

    end

    def first_run force: false
      create_tables

      # uh do we really need these?

      @user = Class.new Sequel::Model(db[:user])  do
        one_to_many :token, key: :user
      end

      @token = Class.new Sequel::Model(db[:token]) do
        one_to_many :usage, key: :token
        many_to_one :user
      end

      @usage = Class.new Sequel::Model(db[:usage]) do
        many_to_one :token
      end
    end

    public

    attr_reader :db, :user, :token, :usage

    def initialize dsn, create: true
      @db = Sequel.connect dsn

      first_run if create
    end

    def initialized?
      tables = [:user, :token, :usage]
      ok = tables.select { |t| db.table_exists? t }
      ok == tables
    end

    def initialize!
      first_run force: true
    end

    def new_user principal, email: ''
      @user
    end

    def new_token principal, cookie: false
    end

    def token_for principal, cookie: false
    end

    def user_for token, cookie: false
      uuid  = UUID::NCName::from_ncname token, version: 1
      out   = @token.join(:user).select(S[:user][:principal], :expires).
        where(token: uuid, slug: !cookie)
      if out.first
        out.first.principal
      end
    end

    def seen_token token, when: DateTime.now
    end
  end
end
