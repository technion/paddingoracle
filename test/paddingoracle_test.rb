require 'test_helper'

class PaddingoracleTest < Minitest::Test
  Blocksize = 8
  def test_that_it_has_a_version_number
    refute_nil ::Paddingoracle::VERSION
  end

  def test_it_does_something_useful
    key = Paddingoracle::TESTKEY
    iv = Paddingoracle::TESTIV

    plaintext = "username here and over here"
    cipher = OpenSSL::Cipher.new("des-cbc")
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    encrypted = cipher.update(plaintext) + cipher.final

    # Prepend the iv to reflect the real world
    encrypted = iv + encrypted

    plain_cracked = Paddingoracle::recover_all_blocks(encrypted)
    assert_equal(plain_cracked, plaintext)

  end

end
