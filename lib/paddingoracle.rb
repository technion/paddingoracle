require "paddingoracle/version"
require 'openssl'
require 'base64'
require 'uri'

module Paddingoracle
  extend self

  def remove_pad(str)
    # Remove PKCS #7 padding
    raise "Incompatible remove_pad input" unless str.kind_of? String
    last = str[-1,1]
    raise "Invalid padding" unless last.ord > 0  && last.ord <= str.size

    padstr = last.chr * last.ord

    padstr = Regexp.escape(padstr)
    unless /#{padstr}$/.match(str)
        raise "Invalid padding"
    end

    return str[0..(str.length-last.ord)-1]
  end

  def recover_block(enc, prevblock, blocksize)
      #For a single CBC-encrypted block, utilise padding Oracle to 
      #recover plaintext
      if enc.length != blocksize || prevblock.length != blocksize
          raise "Incorrect block size to recover"
      end
      ret = "" 
      gen = ""
      (0..blocksize-1).to_a.reverse.each do |k| #For each byte in block
          (0..256).each { |n|
              if n == 256
                  #Should break before this point. n is only valid in 0-255
                  puts "Dumping #{ret}"
                  raise "Failed to find a value"
              end
              testblock = 'A' * k + n.chr + gen + enc 
              puts testblock.unpack('H*').join
              if testblock.length != 2*blocksize
                  raise "Test block had incorrect blocksize"
              end
              #puts "Lengths are #{testblock.length}"
              begin
                  decrypt_oracle(testblock)
              rescue NoMethodError
                  fail "Function decrypt_oracle function not written"
              rescue StandardError
                  #The decrypt_oracle will raise this if the padding is invalid
                  next
              end
              b = (n.ord ^ (blocksize-k).ord ^ prevblock[k].ord).ord 
              #Debugging
              ret = b.chr + ret 
              break #No need to continue once identified
          }
          gen = ret.bytes.map.with_index{ |x, i|
              ((blocksize-k+1).ord ^ x.ord ^ prevblock[k+i].ord).chr
              }.join

      end
      return ret
  end  

  def recover_all_blocks(enc, blocksize)
      #Cycle through each Blocksize block and gather results
      #Strip PKCS#7 padding before returning
      raise "Invalid block" unless enc.length % blocksize == 0
      ret = ""
      prevblock = enc[0..blocksize-1]
      enc = enc[blocksize..enc.length-1]
      puts "we have #{enc.length} in length"
      (0..enc.length-blocksize).step(blocksize) do |n|
          block = enc[n..n+blocksize-1]
          ret += recover_block(block, prevblock, blocksize)
          prevblock = block
      end
      ret = remove_pad(ret)
      return ret
  end

end

