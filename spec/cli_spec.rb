require 'spec_helper'
require 'clipboard'
require 'jwt'

RSpec.describe 'jwtgen CLI', type: :aruba do
  context 'with no options provided' do
    it 'successfully finishes' do
      run('jwtgen')
      stop_all_commands
      expect(last_command_started).to be_successfully_executed
    end

    it 'displays help' do
      run('jwtgen')
      stop_all_commands
      expect(last_command_started.output).to include('Usage: jwtgen [options]')
    end
  end

  it 'with -h option displays help' do
    run('jwtgen -h')
    stop_all_commands
    expect(last_command_started.output).to include('Usage: jwtgen [options]')

    run('jwtgen --help')
    stop_all_commands
    expect(last_command_started.output).to include('Usage: jwtgen [options]')
  end

  it 'with invalid option displays error message' do
    run('jwtgen --invalidoption')
    stop_all_commands
    expect(last_command_started).to have_output('invalid option: --invalidoption')
  end

  context 'with incorrect input' do
    it 'validates user_id option presence' do
      run('jwtgen -e 123')
      stop_all_commands
      expect(last_command_started.output).to include('required `user_id` parameter is missing.')
    end

    it 'validates email option presence' do
      run('jwtgen -u 123')
      stop_all_commands
      expect(last_command_started.output).to include('required `email` parameter is missing.')
    end

    it 'validates email option value format' do
      run('jwtgen -u 123 -e user')
      stop_all_commands
      expect(last_command_started.output).to include('`email` parameter value format is invalid.')
    end

    it 'validates key parameter presence in case algorithm is not `none`' do
      run('jwtgen -u 123 -e user@email.com -a HS256')
      stop_all_commands
      expect(last_command_started.output).to include('required `key` parameter is missing.')
    end

    it 'displays error in case unknown algorithm' do
      run('jwtgen -u 123 -e user@email.com -a UNKNOWN -k SecretKey')
      stop_all_commands
      expect(last_command_started).to have_output('Unsupported signing method')
    end
  end

  context 'with correct input' do
    it 'generates token' do
      run('jwtgen -u 123 -e user@email.com -a HS256 -k SecretKey')
      stop_all_commands
      expect(last_command_started).to have_output('JWT has been copied to clipboard.')
    end

    it 'copies generated token to clipboard' do
      Clipboard.clear
      run('jwtgen -u 123 -e user@email.com -a HS256 -k SecretKey -p key1=value1,key2=value2')
      stop_all_commands
      expect(Clipboard.paste).not_to be_empty
      expect(JWT.decode(Clipboard.paste, 'SecretKey', true, algorithm: 'HS256').first).to eq(
        {'user_id' => '123', 'email' => 'user@email.com', 'key1' => 'value1', 'key2' => 'value2'}
      )
    end
  end
end
