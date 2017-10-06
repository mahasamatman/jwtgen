require 'jwtgen/version'
require 'jwt'

class Jwtgen
  EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  AVAILABLE_ALGORITHMS = %w(none HS256 HS512256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512)

  attr_accessor :payload

  def initialize(options={})
    options[:algorithm] ||= 'none'
    raise(ArgumentError, 'required `user_id` parameter is missing.') if options[:user_id].to_s.length == 0
    raise(ArgumentError, 'required `email` parameter is missing.') if options[:email].to_s.length == 0
    raise(ArgumentError, '`email` parameter value format is invalid.') unless options[:email] =~ EMAIL_REGEX
    raise(ArgumentError, 'required `key` parameter is missing.') if options[:algorithm] != 'none' && options[:key].to_s.length == 0

    @algorithm = options[:algorithm]
    @key = options[:key]

    additional_payload = Hash[options[:payload].to_a.map{ |el| el.split('=') }]

    @payload = additional_payload.merge({'user_id' => options[:user_id], 'email' => options[:email]})
  end

  def generate_token
    JWT.encode(@payload, @key, @algorithm)
  end
end
