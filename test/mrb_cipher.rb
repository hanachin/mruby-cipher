# answer test values
# http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf

def b(hex)
  [hex].pack("H*")
end

def encrypt(key, iv, encrypted, mode)
  cipher = Cipher.new(mode)
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv
  cipher.padding = 0
  cipher.update(encrypted) + cipher.final
end

def decrypt(key, iv, encrypted, mode)
  cipher = Cipher.new(mode)
  cipher.decrypt
  cipher.key = key
  cipher.iv = iv
  cipher.padding = 0
  cipher.update(encrypted) + cipher.final
end

def assert_cipher(plaintext, encrypted, key, iv, mode = 'AES-256-CBC')
  plaintext, encrypted, key, iv = b(plaintext), b(encrypted), b(key), b(iv)

  assert_equal(plaintext) do
    decrypt(key, iv, encrypted, mode)
  end

  assert_equal(encrypted) do
    encrypt(key, iv, plaintext, mode)
  end
end

gf_sbox = <<EOS
014730f80ac625fe84f026c60bfd547d | 5c9d844ed46f9885085e5d6a4f94c7d7
0b24af36193ce4665f2825d7b4749c98 | a9ff75bd7cf6613d3731c77c3b6d0c04
761c1fe41a18acf20d241650611d90f1 | 623a52fcea5d443e48d9181ab32c7421
8a560769d605868ad80d819bdba03771 | 38f2c7ae10612415d27ca190d27da8b4
91fbef2d15a97816060bee1feaa49afe | 1bc704f1bce135ceb810341b216d7abe
EOS

key_sbox = <<EOS
46f2fb342d6f0ab477476fc501242c5f | c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558
4bf3b0a69aeb6657794f2901b1440ad4 | 28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64
352065272169abf9856843927d0674fd | c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c
4307456a9e67813b452e15fa8fffe398 | 984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627
4663446607354989477a5c6f0f007ef4 | b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f
531c2c38344578b84d50b3c917bbb6e1 | 1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9
fc6aec906323480005c58e7e1ab004ad | dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf
a3944b95ca0b52043584ef02151926a8 | f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9
a74289fe73a4c123ca189ea1e1b49ad5 | 797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e
b91d4ea4488644b56cf0812fa7fcf5fc | 6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707
304f81ab61a80c2e743b94d5002a126b | ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc
649a71545378c783e368c9ade7114f6c | 13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887
47cb030da2ab051dfc6c4bf6910d12bb | 07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee
798c7c005dee432b2c8ea5dfa381ecc3 | 90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1
637c31dc2591a07636f646b72daabbe7 | b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07
179a49c712154bbffbe6e7a84a18e220 | fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e
EOS

var_text = <<EOS
80000000000000000000000000000000 | ddc6bf790c15760d8d9aeb6f9a75fd4e
c0000000000000000000000000000000 | 0a6bdc6d4c1e6280301fd8e97ddbe601
e0000000000000000000000000000000 | 9b80eefb7ebe2d2b16247aa0efc72f5d
f0000000000000000000000000000000 | 7f2c5ece07a98d8bee13c51177395ff7
f8000000000000000000000000000000 | 7818d800dcf6f4be1e0e94f403d1e4c2
fc000000000000000000000000000000 | e74cd1c92f0919c35a0324123d6177d3
fe000000000000000000000000000000 | 8092a4dcf2da7e77e93bdd371dfed82e
ff000000000000000000000000000000 | 49af6b372135acef10132e548f217b17
ff800000000000000000000000000000 | 8bcd40f94ebb63b9f7909676e667f1e7
ffc00000000000000000000000000000 | fe1cffb83f45dcfb38b29be438dbd3ab
ffe00000000000000000000000000000 | 0dc58a8d886623705aec15cb1e70dc0e
fff00000000000000000000000000000 | c218faa16056bd0774c3e8d79c35a5e4
fff80000000000000000000000000000 | 047bba83f7aa841731504e012208fc9e
fffc0000000000000000000000000000 | dc8f0e4915fd81ba70a331310882f6da
fffe0000000000000000000000000000 | 1569859ea6b7206c30bf4fd0cbfac33c
ffff0000000000000000000000000000 | 300ade92f88f48fa2df730ec16ef44cd
ffff8000000000000000000000000000 | 1fe6cc3c05965dc08eb0590c95ac71d0
ffffc000000000000000000000000000 | 59e858eaaa97fec38111275b6cf5abc0
ffffe000000000000000000000000000 | 2239455e7afe3b0616100288cc5a723b
fffff000000000000000000000000000 | 3ee500c5c8d63479717163e55c5c4522
fffff800000000000000000000000000 | d5e38bf15f16d90e3e214041d774daa8
fffffc00000000000000000000000000 | b1f4066e6f4f187dfe5f2ad1b17819d0
fffffe00000000000000000000000000 | 6ef4cc4de49b11065d7af2909854794a
ffffff00000000000000000000000000 | ac86bc606b6640c309e782f232bf367f
ffffff80000000000000000000000000 | 36aff0ef7bf3280772cf4cac80a0d2b2
ffffffc0000000000000000000000000 | 1f8eedea0f62a1406d58cfc3ecea72cf
ffffffe0000000000000000000000000 | abf4154a3375a1d3e6b1d454438f95a6
fffffff0000000000000000000000000 | 96f96e9d607f6615fc192061ee648b07
fffffff8000000000000000000000000 | cf37cdaaa0d2d536c71857634c792064
fffffffc000000000000000000000000 | fbd6640c80245c2b805373f130703127
fffffffe000000000000000000000000 | 8d6a8afe55a6e481badae0d146f436db
ffffffff000000000000000000000000 | 6a4981f2915e3e68af6c22385dd06756
ffffffff800000000000000000000000 | 42a1136e5f8d8d21d3101998642d573b
ffffffffc00000000000000000000000 | 9b471596dc69ae1586cee6158b0b0181
ffffffffe00000000000000000000000 | 753665c4af1eff33aa8b628bf8741cfd
fffffffff00000000000000000000000 | 9a682acf40be01f5b2a4193c9a82404d
fffffffff80000000000000000000000 | 54fafe26e4287f17d1935f87eb9ade01
fffffffffc0000000000000000000000 | 49d541b2e74cfe73e6a8e8225f7bd449
fffffffffe0000000000000000000000 | 11a45530f624ff6f76a1b3826626ff7b
ffffffffff0000000000000000000000 | f96b0c4a8bc6c86130289f60b43b8fba
ffffffffff8000000000000000000000 | 48c7d0e80834ebdc35b6735f76b46c8b
ffffffffffc000000000000000000000 | 2463531ab54d66955e73edc4cb8eaa45
ffffffffffe000000000000000000000 | ac9bd8e2530469134b9d5b065d4f565b
fffffffffff000000000000000000000 | 3f5f9106d0e52f973d4890e6f37e8a00
fffffffffff800000000000000000000 | 20ebc86f1304d272e2e207e59db639f0
fffffffffffc00000000000000000000 | e67ae6426bf9526c972cff072b52252c
fffffffffffe00000000000000000000 | 1a518dddaf9efa0d002cc58d107edfc8
ffffffffffff00000000000000000000 | ead731af4d3a2fe3b34bed047942a49f
ffffffffffff80000000000000000000 | b1d4efe40242f83e93b6c8d7efb5eae9
ffffffffffffc0000000000000000000 | cd2b1fec11fd906c5c7630099443610a
ffffffffffffe0000000000000000000 | a1853fe47fe29289d153161d06387d21
fffffffffffff0000000000000000000 | 4632154179a555c17ea604d0889fab14
fffffffffffff8000000000000000000 | dd27cac6401a022e8f38f9f93e774417
fffffffffffffc000000000000000000 | c090313eb98674f35f3123385fb95d4d
fffffffffffffe000000000000000000 | cc3526262b92f02edce548f716b9f45c
ffffffffffffff000000000000000000 | c0838d1a2b16a7c7f0dfcc433c399c33
ffffffffffffff800000000000000000 | 0d9ac756eb297695eed4d382eb126d26
ffffffffffffffc00000000000000000 | 56ede9dda3f6f141bff1757fa689c3e1
ffffffffffffffe00000000000000000 | 768f520efe0f23e61d3ec8ad9ce91774
fffffffffffffff00000000000000000 | b1144ddfa75755213390e7c596660490
fffffffffffffff80000000000000000 | 1d7c0c4040b355b9d107a99325e3b050
fffffffffffffffc0000000000000000 | d8e2bb1ae8ee3dcf5bf7d6c38da82a1a
fffffffffffffffe0000000000000000 | faf82d178af25a9886a47e7f789b98d7
ffffffffffffffff0000000000000000 | 9b58dbfd77fe5aca9cfc190cd1b82d19
ffffffffffffffff8000000000000000 | 77f392089042e478ac16c0c86a0b5db5
ffffffffffffffffc000000000000000 | 19f08e3420ee69b477ca1420281c4782
ffffffffffffffffe000000000000000 | a1b19beee4e117139f74b3c53fdcb875
fffffffffffffffff000000000000000 | a37a5869b218a9f3a0868d19aea0ad6a
fffffffffffffffff800000000000000 | bc3594e865bcd0261b13202731f33580
fffffffffffffffffc00000000000000 | 811441ce1d309eee7185e8c752c07557
fffffffffffffffffe00000000000000 | 959971ce4134190563518e700b9874d1
ffffffffffffffffff00000000000000 | 76b5614a042707c98e2132e2e805fe63
ffffffffffffffffff80000000000000 | 7d9fa6a57530d0f036fec31c230b0cc6
ffffffffffffffffffc0000000000000 | 964153a83bf6989a4ba80daa91c3e081
ffffffffffffffffffe0000000000000 | a013014d4ce8054cf2591d06f6f2f176
fffffffffffffffffff0000000000000 | d1c5f6399bf382502e385eee1474a869
fffffffffffffffffff8000000000000 | 0007e20b8298ec354f0f5fe7470f36bd
fffffffffffffffffffc000000000000 | b95ba05b332da61ef63a2b31fcad9879
fffffffffffffffffffe000000000000 | 4620a49bd967491561669ab25dce45f4
ffffffffffffffffffff000000000000 | 12e71214ae8e04f0bb63d7425c6f14d5
ffffffffffffffffffff800000000000 | 4cc42fc1407b008fe350907c092e80ac
ffffffffffffffffffffc00000000000 | 08b244ce7cbc8ee97fbba808cb146fda
ffffffffffffffffffffe00000000000 | 39b333e8694f21546ad1edd9d87ed95b
fffffffffffffffffffff00000000000 | 3b271f8ab2e6e4a20ba8090f43ba78f3
fffffffffffffffffffff80000000000 | 9ad983f3bf651cd0393f0a73cccdea50
fffffffffffffffffffffc0000000000 | 8f476cbff75c1f725ce18e4bbcd19b32
fffffffffffffffffffffe0000000000 | 905b6267f1d6ab5320835a133f096f2a
ffffffffffffffffffffff0000000000 | 145b60d6d0193c23f4221848a892d61a
ffffffffffffffffffffff8000000000 | 55cfb3fb6d75cad0445bbc8dafa25b0f
ffffffffffffffffffffffc000000000 | 7b8e7098e357ef71237d46d8b075b0f5
ffffffffffffffffffffffe000000000 | 2bf27229901eb40f2df9d8398d1505ae
fffffffffffffffffffffff000000000 | 83a63402a77f9ad5c1e931a931ecd706
fffffffffffffffffffffff800000000 | 6f8ba6521152d31f2bada1843e26b973
fffffffffffffffffffffffc00000000 | e5c3b8e30fd2d8e6239b17b44bd23bbd
fffffffffffffffffffffffe00000000 | 1ac1f7102c59933e8b2ddc3f14e94baa
ffffffffffffffffffffffff00000000 | 21d9ba49f276b45f11af8fc71a088e3d
ffffffffffffffffffffffff80000000 | 649f1cddc3792b4638635a392bc9bade
ffffffffffffffffffffffffc0000000 | e2775e4b59c1bc2e31a2078c11b5a08c
ffffffffffffffffffffffffe0000000 | 2be1fae5048a25582a679ca10905eb80
fffffffffffffffffffffffff0000000 | da86f292c6f41ea34fb2068df75ecc29
fffffffffffffffffffffffff8000000 | 220df19f85d69b1b562fa69a3c5beca5
fffffffffffffffffffffffffc000000 | 1f11d5d0355e0b556ccdb6c7f5083b4d
fffffffffffffffffffffffffe000000 | 62526b78be79cb384633c91f83b4151b
ffffffffffffffffffffffffff000000 | 90ddbcb950843592dd47bbef00fdc876
ffffffffffffffffffffffffff800000 | 2fd0e41c5b8402277354a7391d2618e2
ffffffffffffffffffffffffffc00000 | 3cdf13e72dee4c581bafec70b85f9660
ffffffffffffffffffffffffffe00000 | afa2ffc137577092e2b654fa199d2c43
fffffffffffffffffffffffffff00000 | 8d683ee63e60d208e343ce48dbc44cac
fffffffffffffffffffffffffff80000 | 705a4ef8ba2133729c20185c3d3a4763
fffffffffffffffffffffffffffc0000 | 0861a861c3db4e94194211b77ed761b9
fffffffffffffffffffffffffffe0000 | 4b00c27e8b26da7eab9d3a88dec8b031
ffffffffffffffffffffffffffff0000 | 5f397bf03084820cc8810d52e5b666e9
ffffffffffffffffffffffffffff8000 | 63fafabb72c07bfbd3ddc9b1203104b8
ffffffffffffffffffffffffffffc000 | 683e2140585b18452dd4ffbb93c95df9
ffffffffffffffffffffffffffffe000 | 286894e48e537f8763b56707d7d155c8
fffffffffffffffffffffffffffff000 | a423deabc173dcf7e2c4c53e77d37cd1
fffffffffffffffffffffffffffff800 | eb8168313e1cfdfdb5e986d5429cf172
fffffffffffffffffffffffffffffc00 | 27127daafc9accd2fb334ec3eba52323
fffffffffffffffffffffffffffffe00 | ee0715b96f72e3f7a22a5064fc592f4c
ffffffffffffffffffffffffffffff00 | 29ee526770f2a11dcfa989d1ce88830f
ffffffffffffffffffffffffffffff80 | 0493370e054b09871130fe49af730a5a
ffffffffffffffffffffffffffffffc0 | 9b7b940f6c509f9e44a4ee140448ee46
ffffffffffffffffffffffffffffffe0 | 2915be4a1ecfdcbe3e023811a12bb6c7
fffffffffffffffffffffffffffffff0 | 7240e524bc51d8c4d440b1be55d1062c
fffffffffffffffffffffffffffffff8 | da63039d38cb4612b2dc36ba26684b93
fffffffffffffffffffffffffffffffc | 0f59cb5a4b522e2ac56c1a64f558ad9a
fffffffffffffffffffffffffffffffe | 7bfe9d876c6d63c1d035da8fe21c409d
ffffffffffffffffffffffffffffffff | acdace8078a32b1a182bfa4987ca1347
EOS

var_key = <<EOS
8000000000000000000000000000000000000000000000000000000000000000 | e35a6dcb19b201a01ebcfa8aa22b5759
c000000000000000000000000000000000000000000000000000000000000000 | b29169cdcf2d83e838125a12ee6aa400
e000000000000000000000000000000000000000000000000000000000000000 | d8f3a72fc3cdf74dfaf6c3e6b97b2fa6
f000000000000000000000000000000000000000000000000000000000000000 | 1c777679d50037c79491a94da76a9a35
f800000000000000000000000000000000000000000000000000000000000000 | 9cf4893ecafa0a0247a898e040691559
fc00000000000000000000000000000000000000000000000000000000000000 | 8fbb413703735326310a269bd3aa94b2
fe00000000000000000000000000000000000000000000000000000000000000 | 60e32246bed2b0e859e55c1cc6b26502
ff00000000000000000000000000000000000000000000000000000000000000 | ec52a212f80a09df6317021bc2a9819e
ff80000000000000000000000000000000000000000000000000000000000000 | f23e5b600eb70dbccf6c0b1d9a68182c
ffc0000000000000000000000000000000000000000000000000000000000000 | a3f599d63a82a968c33fe26590745970
ffe0000000000000000000000000000000000000000000000000000000000000 | d1ccb9b1337002cbac42c520b5d67722
fff0000000000000000000000000000000000000000000000000000000000000 | cc111f6c37cf40a1159d00fb59fb0488
fff8000000000000000000000000000000000000000000000000000000000000 | dc43b51ab609052372989a26e9cdd714
fffc000000000000000000000000000000000000000000000000000000000000 | 4dcede8da9e2578f39703d4433dc6459
fffe000000000000000000000000000000000000000000000000000000000000 | 1a4c1c263bbccfafc11782894685e3a8
ffff000000000000000000000000000000000000000000000000000000000000 | 937ad84880db50613423d6d527a2823d
ffff800000000000000000000000000000000000000000000000000000000000 | 610b71dfc688e150d8152c5b35ebc14d
ffffc00000000000000000000000000000000000000000000000000000000000 | 27ef2495dabf323885aab39c80f18d8b
ffffe00000000000000000000000000000000000000000000000000000000000 | 633cafea395bc03adae3a1e2068e4b4e
fffff00000000000000000000000000000000000000000000000000000000000 | 6e1b482b53761cf631819b749a6f3724
fffff80000000000000000000000000000000000000000000000000000000000 | 976e6f851ab52c771998dbb2d71c75a9
fffffc0000000000000000000000000000000000000000000000000000000000 | 85f2ba84f8c307cf525e124c3e22e6cc
fffffe0000000000000000000000000000000000000000000000000000000000 | 6bcca98bf6a835fa64955f72de4115fe
ffffff0000000000000000000000000000000000000000000000000000000000 | 2c75e2d36eebd65411f14fd0eb1d2a06
ffffff8000000000000000000000000000000000000000000000000000000000 | bd49295006250ffca5100b6007a0eade
ffffffc000000000000000000000000000000000000000000000000000000000 | a190527d0ef7c70f459cd3940df316ec
ffffffe000000000000000000000000000000000000000000000000000000000 | bbd1097a62433f79449fa97d4ee80dbf
fffffff000000000000000000000000000000000000000000000000000000000 | 07058e408f5b99b0e0f061a1761b5b3b
fffffff800000000000000000000000000000000000000000000000000000000 | 5fd1f13fa0f31e37fabde328f894eac2
fffffffc00000000000000000000000000000000000000000000000000000000 | fc4af7c948df26e2ef3e01c1ee5b8f6f
fffffffe00000000000000000000000000000000000000000000000000000000 | 829fd7208fb92d44a074a677ee9861ac
ffffffff00000000000000000000000000000000000000000000000000000000 | ad9fc613a703251b54c64a0e76431711
ffffffff80000000000000000000000000000000000000000000000000000000 | 33ac9eccc4cc75e2711618f80b1548e8
ffffffffc0000000000000000000000000000000000000000000000000000000 | 2025c74b8ad8f4cda17ee2049c4c902d
ffffffffe0000000000000000000000000000000000000000000000000000000 | f85ca05fe528f1ce9b790166e8d551e7
fffffffff0000000000000000000000000000000000000000000000000000000 | 6f6238d8966048d4967154e0dad5a6c9
fffffffff8000000000000000000000000000000000000000000000000000000 | f2b21b4e7640a9b3346de8b82fb41e49
fffffffffc000000000000000000000000000000000000000000000000000000 | f836f251ad1d11d49dc344628b1884e1
fffffffffe000000000000000000000000000000000000000000000000000000 | 077e9470ae7abea5a9769d49182628c3
ffffffffff000000000000000000000000000000000000000000000000000000 | e0dcc2d27fc9865633f85223cf0d611f
ffffffffff800000000000000000000000000000000000000000000000000000 | be66cfea2fecd6bf0ec7b4352c99bcaa
ffffffffffc00000000000000000000000000000000000000000000000000000 | df31144f87a2ef523facdcf21a427804
ffffffffffe00000000000000000000000000000000000000000000000000000 | b5bb0f5629fb6aae5e1839a3c3625d63
fffffffffff00000000000000000000000000000000000000000000000000000 | 3c9db3335306fe1ec612bdbfae6b6028
fffffffffff80000000000000000000000000000000000000000000000000000 | 3dd5c34634a79d3cfcc8339760e6f5f4
fffffffffffc0000000000000000000000000000000000000000000000000000 | 82bda118a3ed7af314fa2ccc5c07b761
fffffffffffe0000000000000000000000000000000000000000000000000000 | 2937a64f7d4f46fe6fea3b349ec78e38
ffffffffffff0000000000000000000000000000000000000000000000000000 | 225f068c28476605735ad671bb8f39f3
ffffffffffff8000000000000000000000000000000000000000000000000000 | ae682c5ecd71898e08942ac9aa89875c
ffffffffffffc000000000000000000000000000000000000000000000000000 | 5e031cb9d676c3022d7f26227e85c38f
ffffffffffffe000000000000000000000000000000000000000000000000000 | a78463fb064db5d52bb64bfef64f2dda
fffffffffffff000000000000000000000000000000000000000000000000000 | 8aa9b75e784593876c53a00eae5af52b
fffffffffffff800000000000000000000000000000000000000000000000000 | 3f84566df23da48af692722fe980573a
fffffffffffffc00000000000000000000000000000000000000000000000000 | 31690b5ed41c7eb42a1e83270a7ff0e6
fffffffffffffe00000000000000000000000000000000000000000000000000 | 77dd7702646d55f08365e477d3590eda
ffffffffffffff00000000000000000000000000000000000000000000000000 | 4c022ac62b3cb78d739cc67b3e20bb7e
ffffffffffffff80000000000000000000000000000000000000000000000000 | 092fa137ce18b5dfe7906f550bb13370
ffffffffffffffc0000000000000000000000000000000000000000000000000 | 3e0cdadf2e68353c0027672c97144dd3
ffffffffffffffe0000000000000000000000000000000000000000000000000 | d8c4b200b383fc1f2b2ea677618a1d27
fffffffffffffff0000000000000000000000000000000000000000000000000 | 11825f99b0e9bb3477c1c0713b015aac
fffffffffffffff8000000000000000000000000000000000000000000000000 | f8b9fffb5c187f7ddc7ab10f4fb77576
fffffffffffffffc000000000000000000000000000000000000000000000000 | ffb4e87a32b37d6f2c8328d3b5377802
fffffffffffffffe000000000000000000000000000000000000000000000000 | d276c13a5d220f4da9224e74896391ce
ffffffffffffffff000000000000000000000000000000000000000000000000 | 94efe7a0e2e031e2536da01df799c927
ffffffffffffffff800000000000000000000000000000000000000000000000 | 8f8fd822680a85974e53a5a8eb9d38de
ffffffffffffffffc00000000000000000000000000000000000000000000000 | e0f0a91b2e45f8cc37b7805a3042588d
ffffffffffffffffe00000000000000000000000000000000000000000000000 | 597a6252255e46d6364dbeeda31e279c
fffffffffffffffff00000000000000000000000000000000000000000000000 | f51a0f694442b8f05571797fec7ee8bf
fffffffffffffffff80000000000000000000000000000000000000000000000 | 9ff071b165b5198a93dddeebc54d09b5
fffffffffffffffffc0000000000000000000000000000000000000000000000 | c20a19fd5758b0c4bc1a5df89cf73877
fffffffffffffffffe0000000000000000000000000000000000000000000000 | 97120166307119ca2280e9315668e96f
ffffffffffffffffff0000000000000000000000000000000000000000000000 | 4b3b9f1e099c2a09dc091e90e4f18f0a
ffffffffffffffffff8000000000000000000000000000000000000000000000 | eb040b891d4b37f6851f7ec219cd3f6d
ffffffffffffffffffc000000000000000000000000000000000000000000000 | 9f0fdec08b7fd79aa39535bea42db92a
ffffffffffffffffffe000000000000000000000000000000000000000000000 | 2e70f168fc74bf911df240bcd2cef236
fffffffffffffffffff000000000000000000000000000000000000000000000 | 462ccd7f5fd1108dbc152f3cacad328b
fffffffffffffffffff800000000000000000000000000000000000000000000 | a4af534a7d0b643a01868785d86dfb95
fffffffffffffffffffc00000000000000000000000000000000000000000000 | ab980296197e1a5022326c31da4bf6f3
fffffffffffffffffffe00000000000000000000000000000000000000000000 | f97d57b3333b6281b07d486db2d4e20c
ffffffffffffffffffff00000000000000000000000000000000000000000000 | f33fa36720231afe4c759ade6bd62eb6
ffffffffffffffffffff80000000000000000000000000000000000000000000 | fdcfac0c02ca538343c68117e0a15938
ffffffffffffffffffffc0000000000000000000000000000000000000000000 | ad4916f5ee5772be764fc027b8a6e539
ffffffffffffffffffffe0000000000000000000000000000000000000000000 | 2e16873e1678610d7e14c02d002ea845
fffffffffffffffffffff0000000000000000000000000000000000000000000 | 4e6e627c1acc51340053a8236d579576
fffffffffffffffffffff8000000000000000000000000000000000000000000 | ab0c8410aeeead92feec1eb430d652cb
fffffffffffffffffffffc000000000000000000000000000000000000000000 | e86f7e23e835e114977f60e1a592202e
fffffffffffffffffffffe000000000000000000000000000000000000000000 | e68ad5055a367041fade09d9a70a794b
ffffffffffffffffffffff000000000000000000000000000000000000000000 | 0791823a3c666bb6162825e78606a7fe
ffffffffffffffffffffff800000000000000000000000000000000000000000 | dcca366a9bf47b7b868b77e25c18a364
ffffffffffffffffffffffc00000000000000000000000000000000000000000 | 684c9efc237e4a442965f84bce20247a
ffffffffffffffffffffffe00000000000000000000000000000000000000000 | a858411ffbe63fdb9c8aa1bfaed67b52
fffffffffffffffffffffff00000000000000000000000000000000000000000 | 04bc3da2179c3015498b0e03910db5b8
fffffffffffffffffffffff80000000000000000000000000000000000000000 | 40071eeab3f935dbc25d00841460260f
fffffffffffffffffffffffc0000000000000000000000000000000000000000 | 0ebd7c30ed2016e08ba806ddb008bcc8
fffffffffffffffffffffffe0000000000000000000000000000000000000000 | 15c6becf0f4cec7129cbd22d1a79b1b8
ffffffffffffffffffffffff0000000000000000000000000000000000000000 | 0aeede5b91f721700e9e62edbf60b781
ffffffffffffffffffffffff8000000000000000000000000000000000000000 | 266581af0dcfbed1585e0a242c64b8df
ffffffffffffffffffffffffc000000000000000000000000000000000000000 | 6693dc911662ae473216ba22189a511a
ffffffffffffffffffffffffe000000000000000000000000000000000000000 | 7606fa36d86473e6fb3a1bb0e2c0adf5
fffffffffffffffffffffffff000000000000000000000000000000000000000 | 112078e9e11fbb78e26ffb8899e96b9a
fffffffffffffffffffffffff800000000000000000000000000000000000000 | 40b264e921e9e4a82694589ef3798262
fffffffffffffffffffffffffc00000000000000000000000000000000000000 | 8d4595cb4fa7026715f55bd68e2882f9
fffffffffffffffffffffffffe00000000000000000000000000000000000000 | b588a302bdbc09197df1edae68926ed9
ffffffffffffffffffffffffff00000000000000000000000000000000000000 | 33f7502390b8a4a221cfecd0666624ba
ffffffffffffffffffffffffff80000000000000000000000000000000000000 | 3d20253adbce3be2373767c4d822c566
ffffffffffffffffffffffffffc0000000000000000000000000000000000000 | a42734a3929bf84cf0116c9856a3c18c
ffffffffffffffffffffffffffe0000000000000000000000000000000000000 | e3abc4939457422bb957da3c56938c6d
fffffffffffffffffffffffffff0000000000000000000000000000000000000 | 972bdd2e7c525130fadc8f76fc6f4b3f
fffffffffffffffffffffffffff8000000000000000000000000000000000000 | 84a83d7b94c699cbcb8a7d9b61f64093
fffffffffffffffffffffffffffc000000000000000000000000000000000000 | ce61d63514aded03d43e6ebfc3a9001f
fffffffffffffffffffffffffffe000000000000000000000000000000000000 | 6c839dd58eeae6b8a36af48ed63d2dc9
ffffffffffffffffffffffffffff000000000000000000000000000000000000 | cd5ece55b8da3bf622c4100df5de46f9
ffffffffffffffffffffffffffff800000000000000000000000000000000000 | 3b6f46f40e0ac5fc0a9c1105f800f48d
ffffffffffffffffffffffffffffc00000000000000000000000000000000000 | ba26d47da3aeb028de4fb5b3a854a24b
ffffffffffffffffffffffffffffe00000000000000000000000000000000000 | 87f53bf620d3677268445212904389d5
fffffffffffffffffffffffffffff00000000000000000000000000000000000 | 10617d28b5e0f4605492b182a5d7f9f6
fffffffffffffffffffffffffffff80000000000000000000000000000000000 | 9aaec4fabbf6fae2a71feff02e372b39
fffffffffffffffffffffffffffffc0000000000000000000000000000000000 | 3a90c62d88b5c42809abf782488ed130
fffffffffffffffffffffffffffffe0000000000000000000000000000000000 | f1f1c5a40899e15772857ccb65c7a09a
ffffffffffffffffffffffffffffff0000000000000000000000000000000000 | 190843d29b25a3897c692ce1dd81ee52
ffffffffffffffffffffffffffffff8000000000000000000000000000000000 | a866bc65b6941d86e8420a7ffb0964db
ffffffffffffffffffffffffffffffc000000000000000000000000000000000 | 8193c6ff85225ced4255e92f6e078a14
ffffffffffffffffffffffffffffffe000000000000000000000000000000000 | 9661cb2424d7d4a380d547f9e7ec1cb9
fffffffffffffffffffffffffffffff000000000000000000000000000000000 | 86f93d9ec08453a071e2e2877877a9c8
fffffffffffffffffffffffffffffff800000000000000000000000000000000 | 27eefa80ce6a4a9d598e3fec365434d2
fffffffffffffffffffffffffffffffc00000000000000000000000000000000 | d62068444578e3ab39ce7ec95dd045dc
fffffffffffffffffffffffffffffffe00000000000000000000000000000000 | b5f71d4dd9a71fe5d8bc8ba7e6ea3048
ffffffffffffffffffffffffffffffff00000000000000000000000000000000 | 6825a347ac479d4f9d95c5cb8d3fd7e9
ffffffffffffffffffffffffffffffff80000000000000000000000000000000 | e3714e94a5778955cc0346358e94783a
ffffffffffffffffffffffffffffffffc0000000000000000000000000000000 | d836b44bb29e0c7d89fa4b2d4b677d2a
ffffffffffffffffffffffffffffffffe0000000000000000000000000000000 | 5d454b75021d76d4b84f873a8f877b92
fffffffffffffffffffffffffffffffff0000000000000000000000000000000 | c3498f7eced2095314fc28115885b33f
fffffffffffffffffffffffffffffffff8000000000000000000000000000000 | 6e668856539ad8e405bd123fe6c88530
fffffffffffffffffffffffffffffffffc000000000000000000000000000000 | 8680db7f3a87b8605543cfdbe6754076
fffffffffffffffffffffffffffffffffe000000000000000000000000000000 | 6c5d03b13069c3658b3179be91b0800c
ffffffffffffffffffffffffffffffffff000000000000000000000000000000 | ef1b384ac4d93eda00c92add0995ea5f
ffffffffffffffffffffffffffffffffff800000000000000000000000000000 | bf8115805471741bd5ad20a03944790f
ffffffffffffffffffffffffffffffffffc00000000000000000000000000000 | c64c24b6894b038b3c0d09b1df068b0b
ffffffffffffffffffffffffffffffffffe00000000000000000000000000000 | 3967a10cffe27d0178545fbf6a40544b
fffffffffffffffffffffffffffffffffff00000000000000000000000000000 | 7c85e9c95de1a9ec5a5363a8a053472d
fffffffffffffffffffffffffffffffffff80000000000000000000000000000 | a9eec03c8abec7ba68315c2c8c2316e0
fffffffffffffffffffffffffffffffffffc0000000000000000000000000000 | cac8e414c2f388227ae14986fc983524
fffffffffffffffffffffffffffffffffffe0000000000000000000000000000 | 5d942b7f4622ce056c3ce3ce5f1dd9d6
ffffffffffffffffffffffffffffffffffff0000000000000000000000000000 | d240d648ce21a3020282c3f1b528a0b6
ffffffffffffffffffffffffffffffffffff8000000000000000000000000000 | 45d089c36d5c5a4efc689e3b0de10dd5
ffffffffffffffffffffffffffffffffffffc000000000000000000000000000 | b4da5df4becb5462e03a0ed00d295629
ffffffffffffffffffffffffffffffffffffe000000000000000000000000000 | dcf4e129136c1a4b7a0f38935cc34b2b
fffffffffffffffffffffffffffffffffffff000000000000000000000000000 | d9a4c7618b0ce48a3d5aee1a1c0114c4
fffffffffffffffffffffffffffffffffffff800000000000000000000000000 | ca352df025c65c7b0bf306fbee0f36ba
fffffffffffffffffffffffffffffffffffffc00000000000000000000000000 | 238aca23fd3409f38af63378ed2f5473
fffffffffffffffffffffffffffffffffffffe00000000000000000000000000 | 59836a0e06a79691b36667d5380d8188
ffffffffffffffffffffffffffffffffffffff00000000000000000000000000 | 33905080f7acf1cdae0a91fc3e85aee4
ffffffffffffffffffffffffffffffffffffff80000000000000000000000000 | 72c9e4646dbc3d6320fc6689d93e8833
ffffffffffffffffffffffffffffffffffffffc0000000000000000000000000 | ba77413dea5925b7f5417ea47ff19f59
ffffffffffffffffffffffffffffffffffffffe0000000000000000000000000 | 6cae8129f843d86dc786a0fb1a184970
fffffffffffffffffffffffffffffffffffffff0000000000000000000000000 | fcfefb534100796eebbd990206754e19
fffffffffffffffffffffffffffffffffffffff8000000000000000000000000 | 8c791d5fdddf470da04f3e6dc4a5b5b5
fffffffffffffffffffffffffffffffffffffffc000000000000000000000000 | c93bbdc07a4611ae4bb266ea5034a387
fffffffffffffffffffffffffffffffffffffffe000000000000000000000000 | c102e38e489aa74762f3efc5bb23205a
ffffffffffffffffffffffffffffffffffffffff000000000000000000000000 | 93201481665cbafc1fcc220bc545fb3d
ffffffffffffffffffffffffffffffffffffffff800000000000000000000000 | 4960757ec6ce68cf195e454cfd0f32ca
ffffffffffffffffffffffffffffffffffffffffc00000000000000000000000 | feec7ce6a6cbd07c043416737f1bbb33
ffffffffffffffffffffffffffffffffffffffffe00000000000000000000000 | 11c5413904487a805d70a8edd9c35527
fffffffffffffffffffffffffffffffffffffffff00000000000000000000000 | 347846b2b2e36f1f0324c86f7f1b98e2
fffffffffffffffffffffffffffffffffffffffff80000000000000000000000 | 332eee1a0cbd19ca2d69b426894044f0
fffffffffffffffffffffffffffffffffffffffffc0000000000000000000000 | 866b5b3977ba6efa5128efbda9ff03cd
fffffffffffffffffffffffffffffffffffffffffe0000000000000000000000 | cc1445ee94c0f08cdee5c344ecd1e233
ffffffffffffffffffffffffffffffffffffffffff0000000000000000000000 | be288319029363c2622feba4b05dfdfe
ffffffffffffffffffffffffffffffffffffffffff8000000000000000000000 | cfd1875523f3cd21c395651e6ee15e56
ffffffffffffffffffffffffffffffffffffffffffc000000000000000000000 | cb5a408657837c53bf16f9d8465dce19
ffffffffffffffffffffffffffffffffffffffffffe000000000000000000000 | ca0bf42cb107f55ccff2fc09ee08ca15
fffffffffffffffffffffffffffffffffffffffffff000000000000000000000 | fdd9bbb4a7dc2e4a23536a5880a2db67
fffffffffffffffffffffffffffffffffffffffffff800000000000000000000 | ede447b362c484993dec9442a3b46aef
fffffffffffffffffffffffffffffffffffffffffffc00000000000000000000 | 10dffb05904bff7c4781df780ad26837
fffffffffffffffffffffffffffffffffffffffffffe00000000000000000000 | c33bc13e8de88ac25232aa7496398783
ffffffffffffffffffffffffffffffffffffffffffff00000000000000000000 | ca359c70803a3b2a3d542e8781dea975
ffffffffffffffffffffffffffffffffffffffffffff80000000000000000000 | bcc65b526f88d05b89ce8a52021fdb06
ffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000 | db91a38855c8c4643851fbfb358b0109
ffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000 | ca6e8893a114ae8e27d5ab03a5499610
fffffffffffffffffffffffffffffffffffffffffffff0000000000000000000 | 6629d2b8df97da728cdd8b1e7f945077
fffffffffffffffffffffffffffffffffffffffffffff8000000000000000000 | 4570a5a18cfc0dd582f1d88d5c9a1720
fffffffffffffffffffffffffffffffffffffffffffffc000000000000000000 | 72bc65aa8e89562e3f274d45af1cd10b
fffffffffffffffffffffffffffffffffffffffffffffe000000000000000000 | 98551da1a6503276ae1c77625f9ea615
ffffffffffffffffffffffffffffffffffffffffffffff000000000000000000 | 0ddfe51ced7e3f4ae927daa3fe452cee
ffffffffffffffffffffffffffffffffffffffffffffff800000000000000000 | db826251e4ce384b80218b0e1da1dd4c
ffffffffffffffffffffffffffffffffffffffffffffffc00000000000000000 | 2cacf728b88abbad7011ed0e64a1680c
ffffffffffffffffffffffffffffffffffffffffffffffe00000000000000000 | 330d8ee7c5677e099ac74c9994ee4cfb
fffffffffffffffffffffffffffffffffffffffffffffff00000000000000000 | edf61ae362e882ddc0167474a7a77f3a
fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000 | 6168b00ba7859e0970ecfd757efecf7c
fffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000 | d1415447866230d28bb1ea18a4cdfd02
fffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000 | 516183392f7a8763afec68a060264141
ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000 | 77565c8d73cfd4130b4aa14d8911710f
ffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000 | 37232a4ed21ccc27c19c9610078cabac
ffffffffffffffffffffffffffffffffffffffffffffffffc000000000000000 | 804f32ea71828c7d329077e712231666
ffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000 | d64424f23cb97215e9c2c6f28d29eab7
fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000 | 023e82b533f68c75c238cebdb2ee89a2
fffffffffffffffffffffffffffffffffffffffffffffffff800000000000000 | 193a3d24157a51f1ee0893f6777417e7
fffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000 | 84ecacfcd400084d078612b1945f2ef5
fffffffffffffffffffffffffffffffffffffffffffffffffe00000000000000 | 1dcd8bb173259eb33a5242b0de31a455
ffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000 | 35e9eddbc375e792c19992c19165012b
ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000 | 8a772231c01dfdd7c98e4cfddcc0807a
ffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000 | 6eda7ff6b8319180ff0d6e65629d01c3
ffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000 | c267ef0e2d01a993944dd397101413cb
fffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000 | e9f80e9d845bcc0f62926af72eabca39
fffffffffffffffffffffffffffffffffffffffffffffffffff8000000000000 | 6702990727aa0878637b45dcd3a3b074
fffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000 | 2e2e647d5360e09230a5d738ca33471e
fffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000 | 1f56413c7add6f43d1d56e4f02190330
ffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000 | 69cd0606e15af729d6bca143016d9842
ffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000 | a085d7c1a500873a20099c4caa3c3f5b
ffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000 | 4fc0d230f8891415b87b83f95f2e09d1
ffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000000 | 4327d08c523d8eba697a4336507d1f42
fffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000 | 7a15aab82701efa5ae36ab1d6b76290f
fffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000 | 5bf0051893a18bb30e139a58fed0fa54
fffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000 | 97e8adf65638fd9cdf3bc22c17fe4dbd
fffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000 | 1ee6ee326583a0586491c96418d1a35d
ffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000 | 26b549c2ec756f82ecc48008e529956b
ffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000000 | 70377b6da669b072129e057cc28e9ca5
ffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000 | 9c94b8b0cb8bcc919072262b3fa05ad9
ffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000 | 2fbb83dfd0d7abcb05cd28cad2dfb523
fffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000 | 96877803de77744bb970d0a91f4debae
fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000 | 7379f3370cf6e5ce12ae5969c8eea312
fffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000 | 02dc99fa3d4f98ce80985e7233889313
fffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000 | 1e38e759075ba5cab6457da51844295a
ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000 | 70bed8dbf615868a1f9d9b05d3e7a267
ffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000 | 234b148b8cb1d8c32b287e896903d150
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000 | 294b033df4da853f4be3e243f7e513f4
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000 | 3f58c950f0367160adec45f2441e7411
fffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000 | 37f655536a704e5ace182d742a820cf4
fffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000 | ea7bd6bb63418731aeac790fe42d61e8
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000 | e74a4c999b4c064e48bb1e413f51e5ea
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000 | ba9ebefdb4ccf30f296cecb3bc1943e8
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000 | 3194367a4898c502c13bb7478640a72d
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000 | da797713263d6f33a5478a65ef60d412
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000 | d1ac39bb1ef86b9c1344f214679aa376
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000 | 2fdea9e650532be5bc0e7325337fd363
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000 | d3a204dbd9c2af158b6ca67a5156ce4a
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000 | 3a0a0e75a8da36735aee6684d965a778
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000 | 52fc3e620492ea99641ea168da5b6d52
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000 | d2e0c7f15b4772467d2cfc873000b2ca
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000 | 563531135e0c4d70a38f8bdb190ba04e
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000 | a8a39a0f5663f4c0fe5f2d3cafff421a
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000 | d94b5e90db354c1e42f61fabe167b2c0
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000 | 50e6d3c9b6698a7cd276f96b1473f35a
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000 | 9338f08e0ebee96905d8f2e825208f43
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800 | 8b378c86672aa54a3a266ba19d2580ca
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00 | cca7c3086f5f9511b31233da7cab9160
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00 | 5b40ff4ec9be536ba23035fa4f06064c
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00 | 60eb5af8416b257149372194e8b88749
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80 | 2f005a8aed8a361c92e440c15520cbd1
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0 | 7b03627611678a997717578807a800e2
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 | cf78618f74f6f3696e0a4779b90b5a77
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0 | 03720371a04962eaea0a852e69972858
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8 | 1f8a8133aa8ccf70e2bd3285831ca6b7
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc | 27936bd27fb1468fc8b48bc483321725
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe | b07d4f3e2cd2ef2eb545980754dfea0f
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | 4bf85f1b5d54adbc307b0a048389adcb
EOS

assert("Cipher") do
  gf_sbox.split("\n") do |line|
    plaintext, encrypted = line.split(' | ')
    assert_cipher(plaintext, encrypted, '0' * 64, '0' * 32)
  end

  key_sbox.split("\n") do |line|
    key, encrypted = line.split(' | ')

    assert_cipher('0' * 32, encrypted, key, '0' * 32)
  end

  var_text.split("\n") do |line|
    plaintext, encrypted = line.split(' | ')
    assert_cipher(plaintext, encrypted, '0' * 64, '0' * 32)
  end

  var_key.split("\n") do |line|
    key, encrypted = line.split(' | ')
    assert_cipher('0' * 32, encrypted, key, '0' * 32)
  end
end

assert("Cipher") do
  gf_sbox.split("\n") do |line|
    plaintext, encrypted = line.split(' | ')
    assert_cipher(plaintext, encrypted, '0' * 64, '0' * 32, 'AES-128-CBC')
  end

  key_sbox.split("\n") do |line|
    key, encrypted = line.split(' | ')

    assert_cipher('0' * 32, encrypted, key, '0' * 32, 'AES-128-CBC')
  end

  var_text.split("\n") do |line|
    plaintext, encrypted = line.split(' | ')
    assert_cipher(plaintext, encrypted, '0' * 64, '0' * 32, 'AES-128-CBC')
  end

  var_key.split("\n") do |line|
    key, encrypted = line.split(' | ')
    assert_cipher('0' * 32, encrypted, key, '0' * 32, 'AES-128-CBC')
  end
end

assert("Cipher.ciphers") do
  assert_equal(true, Cipher.ciphers.include?("AES-256-CBC"))
end
