MRuby::Gem::Specification.new('mruby-cipher') do |spec|
  spec.license = 'MIT'
  spec.author  = 'Seiei Miyagi'
  spec.summary  = 'OpenSSL Cipher wrapper'
  spec.linker.libraries << 'crypto'
  spec.add_test_dependency('mruby-pack')
end
