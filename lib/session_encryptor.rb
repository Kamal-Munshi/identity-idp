class SessionEncryptor
  SENSITIVE_KEYS = [
    'first_name', 'middle_name', 'last_name', 'address1', 'address2', 'city', 'state', 'zipcode',
    'zip_code', 'dob', 'phone', 'phone_number', 'ssn', 'prev_address1', 'prev_address2',
    'prev_city', 'prev_state', 'prev_zipcode', 'pii', 'pii_from_doc'
  ]

  def load(value)
    return LegacySessionEncryptor.new.load(value) if should_use_legacy_encryptor_for_read?(value)

    decrypted = encryptor.decrypt(value)

    session = JSON.parse(decrypted, quirks_mode: true).with_indifferent_access
    kms_decrypt_doc_auth_pii!(session)
    kms_decrypt_idv_pii!(session)

    session
  end

  def dump(value)
    return LegacySessionEncryptor.new.dump(value) if should_use_legacy_encryptor_for_write?

    kms_encrypt_pii!(value)
    kms_encrypt_doc_auth_pii!(value)
    kms_encrypt_idv_pii!(value)
    raise 'oops' if contains_sensitive_keys?(value)
    plain = JSON.generate(value, quirks_mode: true)
    raise 'oops' if contains_pii?(plain)
    'v2' + encryptor.encrypt(plain)
  end

  def kms_encrypt(text)
    Base64.encode64(Encryption::KmsClient.new.encrypt(text, 'context' => 'session-encryption'))
  end

  def kms_decrypt(text)
    Encryption::KmsClient.new.decrypt(
      Base64.decode64(text), 'context' => 'session-encryption'
    )
  end

  private

  def kms_encrypt_pii!(session)
    return unless session.dig('warden.user.user.session', :decrypted_pii)
    decrypted_pii = session['warden.user.user.session'].delete(:decrypted_pii)
    session['warden.user.user.session'][:encrypted_pii] = kms_encrypt(decrypted_pii)
    nil
  end

  def kms_encrypt_doc_auth_pii!(session)
    return unless session.dig('warden.user.user.session', 'idv/doc_auth')
    doc_auth_pii = session.dig('warden.user.user.session').delete('idv/doc_auth')
    session['warden.user.user.session']['encrypted_idv/doc_auth'] =
      kms_encrypt(JSON.generate(doc_auth_pii, quirks_mode: true))
    nil
  end

  def kms_decrypt_doc_auth_pii!(session)
    return unless session.dig('warden.user.user.session', 'encrypted_idv/doc_auth')
    doc_auth_pii = session['warden.user.user.session'].delete('encrypted_idv/doc_auth')
    session['warden.user.user.session']['idv/doc_auth'] = JSON.parse(
      kms_decrypt(doc_auth_pii), quirks_mode: true
    )
    nil
  end

  def kms_encrypt_idv_pii!(session)
    return unless session.dig('warden.user.user.session', 'idv')
    idv_pii = session.dig('warden.user.user.session').delete('idv')
    session['warden.user.user.session']['encrypted_idv'] =
      kms_encrypt(JSON.generate(idv_pii, quirks_mode: true))
    nil
  end

  def kms_decrypt_idv_pii!(session)
    return unless session.dig('warden.user.user.session', 'encrypted_idv')
    idv_pii = session['warden.user.user.session'].delete('encrypted_idv')
    session['warden.user.user.session']['idv'] = JSON.parse(kms_decrypt(idv_pii), quirks_mode: true)
    nil
  end

  def contains_pii?(session_string)
    # rubocop:disable Layout/LineLength
    session_string.match?(
      %r{"ssn":|"pii_from_doc"|FAKEY|"address1":|"first_name":|"middle_name":|"last_name":|"address2":|"city":|"state":|"zipcode":|"dob":|"phone":|"prev_address1":|"prev_address2":|"prev_city":|"prev_state":|"prev_zipcode"},
    )
    # rubocop:enable Layout/LineLength
  end

  def contains_sensitive_keys?(hash)
    hash.each do |key, value|
      raise 'no' if SENSITIVE_KEYS.include?(key.to_s)
      contains_sensitive_keys?(value) if value.is_a?(Hash)
    end
  end

  def should_use_legacy_encryptor_for_read?(value)
    ## Legacy ciphertexts will not include a colon and thus will have no header
    header = value.split(':').first
    header != 'v2'
  end

  def should_use_legacy_encryptor_for_write?
    !IdentityConfig.store.session_encryptor_v2_enabled
  end

  def encryptor
    Encryption::Encryptors::AttributeEncryptor.new
  end
end
