require "paddingoracle/version"
require 'openssl'
require 'base64'
require 'uri'

module Paddingoracle
  extend self
  Blocksize = 8
  $iv = 'B' * 8

  def remove_pad(str)
      raise "Incompatible remove_pad input" unless str.kind_of? String
      last = str[-1,1]
      raise "Invalid padding" unless last.ord > 0  && last.ord <= Blocksize

      padstr = last.chr * last.ord

      padstr = Regexp.escape(padstr)
      unless /#{padstr}$/.match(str)
          raise "Invalid padding"
      end

      return str[0..(str.length-last.ord)-1]
  end



  def recover_block(enc, prevblock)
      #For a single CBC-encrypted block, utilise padding Oracle to 
      #recover plaintext
      if enc.length != Blocksize || prevblock.length != Blocksize
          raise "Incorrect block size to recover"
      end
      ret = "" 
      gen = ""
      (0..Blocksize-1).to_a.reverse.each { |k| #For each byte in block
          (0..256).each { |n|
              if n == 256
                  #Should break before this point. n is only valid in 0-255
                  puts "Dumping #{ret}"
                  raise "Failed to find a value"
              end
              testblock = 'A' * k + n.chr + gen + enc 
              puts testblock.unpack('H*').join
              if testblock.length != 2*Blocksize
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
              b = (n.ord ^ (Blocksize-k).ord ^ prevblock[k].ord).ord 
              #Debugging
              ret = b.chr + ret 
              break #No need to continue once identified
          }
          gen = ret.bytes.map.with_index{ |x, i|
              ((Blocksize-k+1).ord ^ x.ord ^ prevblock[k+i].ord).chr}.join

      }
      return ret
  end  

  def recover_all_blocks(enc)
      #Cycle through each Blocksize block and gather results
      #Strip PKCS#7 padding before returning
      raise "Invalid block" unless enc.length % Blocksize == 0
      ret = ""
      prevblock = $iv
      puts "we have #{enc.length} in length"
      (0..enc.length-Blocksize).step(Blocksize) { |n|
          block = enc[n..n+Blocksize-1]
          ret += recover_block(block, prevblock)
          prevblock = block
      }
      ret = remove_pad(ret)
      return ret
  end

end

