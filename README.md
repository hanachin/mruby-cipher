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
