require_relative 'version'
require 'sequel'
module LazyAuth
  class State
    private

    S = Sequel

    def create_tables
      # XXX wrap these in a thing

      unless db.table_exists? :user
        db.create_table :user do
          primary_key :id, type: Integer, primary_key_constraint_name: :pk_user
          String   :principal, null: false, unique: true
          String   :email,     null: false, default: ''
          DateTime :added,     null: false, default: S::CURRENT_TIMESTAMP
          DateTime :disabled,  null: true
        end
      end

      unless db.table_exists? :nonce
        db.create_table :nonce do
          String    :nonce,   null: false, fixed: true, size: 36
          Integer   :user,    null: false
          TrueClass :slug,    null: false, default: false
          TrueClass :oneoff,  null: false, default: false
          DateTime  :added,   null: false, default: S::CURRENT_TIMESTAMP
          DateTime  :expires, null: false, default: Time.at(2**31-1).to_datetime
          primary_key [:nonce, :user], name: :pk_nonce
          unique [:nonce], name: :uk_nonce
          foreign_key [:user], :user,  key: :id, name: :fk_nonce_user
          constraint :ck_nonce,
            :nonce => S.function(:trim, S.function(:lower, :nonce))
        end
      end

      unless db.table_exists? :usage
        db.create_table :usage do
          String   :nonce, null: false, unique: true, fixed: true, size: 36
          String   :ip,    null: false, size: 40
          DateTime :seen,  null: false, default: S::CURRENT_TIMESTAMP
          primary_key [:nonce, :ip], name: :pk_usage
          foreign_key [:nonce], :nonce, name: :fk_usage_nonce
        end
      end

      # cookie and slug nonce tables are identical; maybe we should
      # roll them together? i dunno.

      # for instance does it matter if you can take the nonce directly
      # from the query parameter and plunk it in a cookie? i am
      # inclined to say yes. it does matter. you should not be able to
      # do this. same goes for the other way around.

      # as for the entropy of the nonces, i think 122 bits of uuid is
      # good enough. 
    end

    public

    attr_reader :db, :user, :nonce, :usage

    def initialize dsn
      @db = Sequel.connect dsn

      create_tables

      # uh do we really need these?

      @user = Class.new Sequel::Model(db[:user])  do
        one_to_many :nonce, key: :user
      end

      @nonce = Class.new Sequel::Model(db[:nonce]) do
        one_to_many :usage, key: :nonce
        many_to_one :user
      end

      @usage = Class.new Sequel::Model(db[:usage]) do
        many_to_one :nonce
      end
    end

    def new_user principal, email: ''
      @user
    end

    def new_nonce principal, cookie: false
    end

    def nonce_for principal, cookie: false
    end

    def user_for nonce, cookie: false
      uuid  = UUID::NCName::from_ncname nonce, version: 1
      out   = @nonce.join(:user).select(S[:user][:principal], :expires).
        where(nonce: uuid, slug: !cookie)
      if out.first
        out.first.principal
      end
    end

    def seen_nonce nonce, when: DateTime.now
    end
  end
end
