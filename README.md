mruby-cipher   [![Build Status](https://travis-ci.org/hanachin/mruby-cipher.svg?branch=master)](https://travis-ci.org/hanachin/mruby-cipher)
====

OpenSSL Cipher wrapper.

It is based on CRuby's OpenSSL::Cipher.

Installation
----

Add this line to build_config.rb

```ruby
MRuby::Build.new do |conf|
  conf.gem github: 'hanachin/mruby-cipher'
end
```

or add this line to your aplication's mrbgem.rake

```ruby
MRuby::Gem::Specification.new('your-mrbgem') do |spec|
  spec.add_dependency 'mruby-cipher', github: 'hanachin/mruby-cipher'
end
```

Requirements
----

- OpenSSL library

Usage
----

```ruby
Cipher.ciphers
# => ["AES-128-CBC", "AES-128-CFB", "AES-128-CFB1", "AES-128-CFB8", "AES-128-ECB", "AES-128-OFB", "AES-192-CBC", "AES-192-CFB", "AES-192-CFB1", "AES-192-CFB8", "AES-192-ECB", "AES-192-OFB", "AES-256-CBC", "AES-256-CFB", "AES-256-CFB1", "AES-256-CFB8", "AES-256-ECB", "AES-256-OFB", "AES128", "AES192", "AES256", "BF", "BF-CBC", "BF-CFB", "BF-ECB", "BF-OFB", "CAST", "CAST-cbc", "CAST5-CBC", "CAST5-CFB", "CAST5-ECB", "CAST5-OFB", "DES", "DES-CBC", "DES-CFB", "DES-CFB1", "DES-CFB8", "DES-ECB", "DES-EDE", "DES-EDE-CBC", "DES-EDE-CFB", "DES-EDE-OFB", "DES-EDE3", "DES-EDE3-CBC", "DES-EDE3-CFB", "DES-EDE3-CFB1", "DES-EDE3-CFB8", "DES-EDE3-OFB", "DES-OFB", "DES3", "DESX", "DESX-CBC", "RC2", "RC2-40-CBC", "RC2-64-CBC", "RC2-CBC", "RC2-CFB", "RC2-ECB", "RC2-OFB", "RC4", "RC4-40", "SEED", "SEED-CBC", "SEED-CFB", "SEED-ECB", "SEED-OFB", "aes-128-cbc", "aes-128-cfb", "aes-128-cfb1", "aes-128-cfb8", "aes-128-ecb", "aes-128-ofb", "aes-192-cbc", "aes-192-cfb", "aes-192-cfb1", "aes-192-cfb8", "aes-192-ecb", "aes-192-ofb", "aes-256-cbc", "aes-256-cfb", "aes-256-cfb1", "aes-256-cfb8", "aes-256-ecb", "aes-256-ofb", "aes128", "aes192", "aes256", "bf", "bf-cbc", "bf-cfb", "bf-ecb", "bf-ofb", "blowfish", "cast", "cast-cbc", "cast5-cbc", "cast5-cfb", "cast5-ecb", "cast5-ofb", "des", "des-cbc", "des-cfb", "des-cfb1", "des-cfb8", "des-ecb", "des-ede", "des-ede-cbc", "des-ede-cfb", "des-ede-ofb", "des-ede3", "des-ede3-cbc", "des-ede3-cfb", "des-ede3-cfb1", "des-ede3-cfb8", "des-ede3-ofb", "des-ofb", "des3", "desx", "desx-cbc", "rc2", "rc2-40-cbc", "rc2-64-cbc", "rc2-cbc", "rc2-cfb", "rc2-ecb", "rc2-ofb", "rc4", "rc4-40", "seed", "seed-cbc", "seed-cfb", "seed-ecb", "seed-ofb"]
```

```ruby
cipher = Cipher.new('AES-256-CBC')
cipher.decrypt
cipher.key = key
cipher.iv = iv
cipher.padding = 0
cipher.update(encrypted) + cipher.final
```

```ruby
cipher = Cipher.new('AES-256-CBC')
cipher.encrypt
cipher.key = key
cipher.iv = iv
cipher.padding = 0
cipher.update(plaintext) + cipher.final
```

How to run test
----

    $ git clone https://github.com/hanachin/mruby-cipher.git
    $ cd mruby-cipher
    $ ./test.sh

License
----

MIT
