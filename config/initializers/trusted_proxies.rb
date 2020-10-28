if ENV['TRUSTED_PROXIES']
  Rails.application.config.action_dispatch.trusted_proxies = ENV['TRUSTED_PROXIES'].to_s.split(',').map { |proxy| IPAddr.new(proxy) }
end
