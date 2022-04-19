require 'rails_helper'

RSpec.describe SessionEncryptor do
  describe '#load' do
    context 'with a legacy session ciphertext' do
      it 'decrypts the legacy session' do
        session = { 'foo' => 'bar' }

        ciphertext = LegacySessionEncryptor.new.dump(session)

        result = SessionEncryptor.new.load(ciphertext)

        expect(result).to eq(session)
      end
    end

    context 'with a modern and exciting ciphertext' do
      it 'decrypts the encrypted PII components of the session' do
        session = { 'foo' => 'bar' }

        ciphertext = LegacySessionEncryptor.new.dump(session)

        result = SessionEncryptor.new.load(ciphertext)
      end
    end
  end

  describe '#dump' do
    context 'with version 2 encryption enabled' do
      before do
        allow(IdentityConfig.store).to receive(:session_encryptor_v2_enabled).and_return(true)
      end

      it 'encrypts the PII elements of the session' do
        session = { 'warden.user.user.session' => {'idv' => { 'ssn' => 'bar' }}}

        ciphertext = SessionEncryptor.new.dump(session)

        binding.pry
        result = SessionEncryptor.new.load(ciphertext)
        binding.pry
      end
    end

    context 'whithout version 2 encryption enabled' do
      before do
        allow(IdentityConfig.store).to receive(:session_encryptor_v2_enabled).and_return(false)
      end

      it 'encrypts the session with the legacy encryptor' do
        session = { 'foo' => 'bar' }
        ciphertext = SessionEncryptor.new.dump(session)
        decrypted_session = LegacySessionEncryptor.new.load(ciphertext)

        expect(decrypted_session).to eq(session)
      end
    end
  end
end
