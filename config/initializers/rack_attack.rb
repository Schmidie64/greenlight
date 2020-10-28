# Class that holds all configuration in corresponding methods.
module Greenlight::Throttle
  # Returns a hash containing the keys `class`, `params` and `named_params`. For more information see in the
  # `throttle_default.yml`.
  #
  # @!method cache_config
  # @return Hash
  def self.cache_config
    self.config[:cache]
  end

  # Returns a hash with symbolized key names containing the config from the YAML-File. If there is no custom config
  # file specified by the environment variable `THROTTLE_CONFIG`, the config gets loaded from `throttle_default.yml`.
  #
  # @!method config
  # @return Hash
  def self.config
    (if !ENV['THROTTLE_CONFIG']
       YAML.load_file("#{Rails.root.to_s}/config/initializers/throttle_default.yml").deep_symbolize_keys
     else
       YAML.load_file(ENV['THROTTLE_CONFIG']).deep_symbolize_keys
     end)[:throttle]
  end

  # Returns an array containing the discriminators by which values the amount of requests gets calculated. For more
  # information see in the `throttle_default.yml`.
  #
  # @!method discriminators
  # @return Array
  def self.discriminators
    self.config[:discriminators] || []
  end

  # Returns the limit of requests that are allowed for the `protected_paths` in the specified `period`.
  #
  # @!method limit
  # @return Integer
  def self.limit
    self.config[:limit]
  end

  # Returns an array containing the params discriminators by which values the amount of requests gets calculated. For
  # more information see in the `throttle_default.yml`.
  #
  # @!method params_discriminators
  # @return Array
  def self.params_discriminators
    self.config[:params_discriminators] || []
  end

  # Returns the duration in seconds since the latest request where the amount of requests gets limited/counted.
  #
  # @!method period
  # @return Duration
  def self.period
    self.config[:period].seconds
  end

  # Returns an array of hashes that contain the path and the HTTP methods which should be protected by rack attack.
  #
  # @!method protected_paths
  # @return [{path => String, methods => [String]}]
  def self.protected_paths
    (self.config[:protected_paths] || []).map do |path_def|
      {
          path: Greenlight::Application.config.relative_url_root + (path_def.is_a?(String) ? path_def : path_def[:path]),
          methods: path_def.is_a?(String) ? ['POST'] : path_def[:methods]
      }
    end
  end

  # Returns the log level for track events or `nil` if no log level is specified.
  #
  # @!method tracks_log_level
  # @return String|nil
  def self.tracks_log_level
    self.config[:tracks_log_level]
  end

  # Returns an array that contains the trusted ips, which should be ignored when protecting paths.
  #
  # @!method trusted_ips
  # @return
  def self.trusted_ips
    self.config[:trusted_ips] || []
  end

  # Returns the log level for safelist events or `nil` if no log level is specified.
  #
  # @!method tracks_log_level
  # @return String|nil
  def self.safelist_log_level
    self.config[:safelist_log_level]
  end
end

# The configuration of rack attack.
class Rack::Attack
  # Enable or disable rack attack depending on the config
  self.enabled = Greenlight::Throttle.config[:enabled] || true

  # Configure custom caching method if specified
  unless Greenlight::Throttle.cache_config.nil?
    params = Greenlight::Throttle.cache_config[:params] || []
    named_params = Greenlight::Throttle.cache_config[:named_params] || {}

    # Special handling is necessary for the case if no named params (keyword arguments) are specified, since a
    # destructuring of a empty hash leads to errors.
    if named_params.empty?
      self.cache.store = Greenlight::Throttle.cache_config[:class].safe_constantize.new(*params)
    else
      self.cache.store = Greenlight::Throttle.cache_config[:class].safe_constantize.new(*params, **named_params)
    end
  end

  # Safelisting
  Greenlight::Throttle.trusted_ips.each do |ip|
    safelist_ip(ip)
  end

  # Throttling for protected paths and direct request properties
  Greenlight::Throttle.discriminators.each do |discriminator|
    track("protected_paths/#{discriminator[:name]}", limit: Greenlight::Throttle.limit, period: Greenlight::Throttle.period) do |req|
      if req.protected_path?
        req.path_discriminator(discriminator[:property])
      end
    end
  end

  # Throttling for protected paths and params passed by the request
  Greenlight::Throttle.params_discriminators.each do |discriminator|
    track("protected_paths/#{discriminator[:name]}", limit: Greenlight::Throttle.limit, period: Greenlight::Throttle.period) do |req|
      if req.protected_path?
        req.path_discriminator(discriminator[:property], params: true)
      end
    end
  end

  # Adjust the request class that gets passed to the track blocks to simplify the code.
  class Request
    # Returns the value for the specified discriminator for the requested path and methods.
    #
    # @!method path_discriminator
    # @param property [String[]|{paths => String[], property => String[]}]
    # @param params TrueClass|FalseClass Default false
    # @return Object|nil
    def path_discriminator(property, params: false)
      discriminator_property = property.find { |prop|
        prop.is_a?(Array) || !prop[:paths].find { |path_def|
          (Greenlight::Application.config.relative_url_root + path_def) == path
        }.nil?
      }
      discriminator_property = discriminator_property[:property] if discriminator_property.is_a?(Hash)

      return send('params').dig(*discriminator_property) if params && !discriminator_property.nil?
      return send(*discriminator_property) unless discriminator_property.nil?
    end

    # Returns a boolean value that indicates whether the requested path is a protected path or not.
    #
    # @!method protected_path?
    # @return TrueClass|FalseClass
    def protected_path?
      !(Greenlight::Throttle.protected_paths.find do |path_def|
        path == path_def[:path] && path_def[:methods].include?(request_method)
      end).nil?
    end
  end
end

### Logging ###
unless Greenlight::Throttle.safelist_log_level.nil?
  # Logging for Safelist-Events
  ActiveSupport::Notifications.subscribe("safelist.rack_attack") do |_name, _start, _finish, _id, payload|
    Rails.logger.send(Greenlight::Throttle.safelist_log_level, 'Rack-Attack: Safelisted protected path requested from "' + payload[:request].ip + '"') if payload[:request].protected_path?
  end
end

unless Greenlight::Throttle.tracks_log_level.nil?
  # Logging for Track-Events
  ActiveSupport::Notifications.subscribe("track.rack_attack") do |_name, _start, _finish, _id, payload|
    env = payload[:request].env
    Rails.logger.send(Greenlight::Throttle.tracks_log_level, 'Rack-Attack: Matched "' + env['rack.attack.matched'] + '" with discriminator "' + env['rack.attack.match_discriminator'] + '"')
  end
end
