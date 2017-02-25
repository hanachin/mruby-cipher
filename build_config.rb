MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'
  conf.gem '..'

  enable_debug

  conf.enable_test
end
