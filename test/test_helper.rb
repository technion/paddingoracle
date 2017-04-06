$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'paddingoracle'

module Paddingoracle
  TESTKEY = 'A' * 8
  TESTIV = 'B' * 8
  def decrypt_oracle(string)
    decipher = OpenSSL::Cipher.new("des-cbc")
    decipher.reset
    decipher.decrypt
    decipher.key = TESTKEY
    decipher.iv = TESTIV

    # Will automatically throw an exception if decipher.final fails to
    # remove pad
    decipher.update(string) + decipher.final
  end
end

require 'minitest/autorun'
