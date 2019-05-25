require 'lazyauth/state'
require 'pathname'
require 'commander'
require 'iso8601'
require 'uri'
require 'yaml'

module LazyAuth
  class CLI
    include Commander::Methods

    DEFAULTS = {
      dsn:    'sqlite://lazyauth.sqlite',
      query:  'knock',
      cookie: 'lazyauth',
      config: 'lazyauth.yml',
    }.freeze

    def run
      program :name,        'lazyauth-cli'
      program :version,     LazyAuth::VERSION
      program :description, 'Command line manager for LazyAuth'

      global_option '-b', '--base-uri URI',
        'A base URI for relative references' do |o|
        @base = URI(o)
      end
      global_option '-c', '--config FILE',
        'The location of the configuration file' do |o|
        @config = Pathname(o)
      end
      global_option '-d', '--dsn STRING',
        'Specify a data source name, overriding configuration' do |o|
        @dsn = o
      end

      command :init do |c|
        c.summary = 'Initializes configuration file and state database.'
        c.syntax = 'init [OPTIONS]'
        c.option '--query-key STRING', 'A URI query key; defaults to `knock`'
        c.option '--cookie-key STRING', 'A cookie key; defaults to `lazyauth`'
        c.option '--expiry STRING', 'Global default expiry, given as a duration'
        c.option '--url-expiry STRING', 'Default expiry duration for URLs'
        c.option '--cookie-expiry STRING', 'Default expiry duration for cookies'
        c.option '--user-var '
        c.option '-l', '--listen HOST',
          'Specify listening address (default localhost)'
        c.option '-p', '--port NUMBER', 'Specify TCP port (default 10101)'
        c.option '-P', '--pid FILE', 'Create a PID file when detached'

        c.action do |_, opts|
          # do this whole thing atomically:

          # check for existence of config file
          # get confirmation if config file already exists
          # complain if not writable
          # write config file

          # check for existence of database
          # complain if database doesn't exist or if i don't have access
          # write database tables

          # now tell the user what i did
        end
      end

      command :mint do |c|
        c.syntax = 'mint [OPTIONS] USERID [URL]'
        c.summary = 'Mints a new URL associated with the given user.'
        c.option '-e', '--email EMAIL',
          'Set the email address for the (new) user'
        c.option '-n', '--new',
          'Force minting a new URL slug even if the current one is still fresh'
        c.option '-x', '--expire',
          'Expire any active URL slugs in circulation (implies --new)'

        c.action do |args, opts|
          # create the user if the user does not exist

          # complain if the url is http
        end
      end

      command :fcgi do |c|
        c.syntax = 'fcgi [OPTIONS]'
        c.summary = 'Runs the LazyAuth FastCGI authenticator.'
        c.option '-l', '--listen HOST',
          'Specify listening address (default localhost)'
        c.option '-p', '--port NUMBER', 'Specify TCP port (default 10101)'
        c.option '-z', '--detach', 'Detach and daemonize the process'
        c.option '-P', '--pid FILE', 'Create a PID file when detached'
        c.action do |args, opts|
          require 'lazyauth'
          require 'rack'
          Rack::Server.start({
            app: LazyAuth::App.new(opts.dsn || 'sqlite://lazyauth.db'),
            server: 'fastcgi',
            environment: 'none',
            daemonize: opts.detach,
            Host: 'localhost',
            Port: 10101,
          })
        end
      end

      default_command :mint

      run!
    end

    def self.run
      new.run
    end
  end
end
