require 'spec_helper'
require 'jwtgen'

RSpec.describe Jwtgen do
  describe '#new' do
    it 'requires user_id option' do
      expect{described_class.new}.to raise_error(ArgumentError, 'required `user_id` parameter is missing.')
    end

    it 'requires email option' do
      expect{described_class.new({user_id: 123})}.to raise_error(ArgumentError, 'required `email` parameter is missing.')
    end

    it 'validates email with regex' do
      expect{described_class.new({user_id: 123, email: 'email.com'})}.to(
        raise_error(ArgumentError, '`email` parameter value format is invalid.')
      )

      expect(described_class.new({user_id: 123, email: 'user@email.com'})).to be_an_instance_of(described_class)
    end

    it 'requires key parameter when algorithm is different from default' do
      expect{described_class.new({user_id: 123, email: 'user@email.com', algorithm: 'HS256'})}.to(
        raise_error(ArgumentError, 'required `key` parameter is missing.')
      )

      expect(described_class.new({user_id: 123, email: 'user@email.com', algorithm: 'HS256', key: 'SecretKey'})).to(
        be_an_instance_of(described_class)
      )
    end

    it 'has additional payload' do
      payload = ['key1=value1', 'key2=value2']
      instance_object = described_class.new({user_id: 123, email: 'user@email.com', payload: payload})

      expect(instance_object.payload.values_at('key1', 'key2')).to match_array(['value1', 'value2'])
    end
  end

  describe '#generate_token' do
    it 'generates unsigned token' do
      options = {user_id: 123, email: 'user@email.com', algorithm: 'none', payload: ['key1=value1', 'key2=value2']}
      instance_object = described_class.new(options)
      token = instance_object.generate_token

      expect(JWT.decode(token, nil, false).first).to eq(instance_object.payload)
    end

    it 'generates HMAC token' do
      options = {user_id: 123, email: 'user@email.com', algorithm: 'HS256', key: 'SecretKey', payload: ['key1=value1', 'key2=value2']}
      instance_object = described_class.new(options)
      token = instance_object.generate_token

      expect(JWT.decode(token, options[:key], true, algorithm: 'HS256').first).to eq(instance_object.payload)
    end

    it 'generates RSA token' do
      rsa_private = OpenSSL::PKey::RSA.generate(2048)
      rsa_public = rsa_private.public_key
      options = {user_id: 123, email: 'user@email.com', algorithm: 'RS256', key: rsa_private, payload: ['key1=value1', 'key2=value2']}
      instance_object = described_class.new(options)
      token = instance_object.generate_token

      expect(JWT.decode(token, rsa_public, true, :algorithm => 'RS256').first).to eq(instance_object.payload)
    end
  end
end
