
Pod::Spec.new do |s|
  s.name         = "RNOMEMOCipher"
  s.version      = "2.3.2"
  s.summary      = "RNOMEMOCipher"
  s.description  = <<-DESC
                  RNOMEMOCipher
                   DESC
  s.homepage     = "https://github.com/telldus/react-native-omemo-cipher.git"
  s.license      = "MIT"
  # s.license      = { :type => "MIT", :file => "FILE_LICENSE" }
  s.author             = { "author" => "rimnesh.fernandez@telldus.com" }
  s.platform     = :ios, "9.0"
  s.source       = { :git => "https://github.com/telldus/react-native-omemo-cipher.git", :tag => "ios" }
  s.requires_arc = true
  s.source_files  = ["libsignal-protocol-c/src/**/*.{h,c}", "ios/*.{h,m}"]
  s.preserve_paths = ["ios/libsignal-protocol-c/*"]
  s.public_header_files = [
  "libsignal-protocol-c/src/signal_protocol.h", 
  "libsignal-protocol-c/src/signal_protocol_types.h", 
  "libsignal-protocol-c/src/curve.h", 
  "libsignal-protocol-c/src/hkdf.h", 
  "libsignal-protocol-c/src/ratchet.h", 
  "libsignal-protocol-c/src/protocol.h", 
  "libsignal-protocol-c/src/session_state.h", 
  "libsignal-protocol-c/src/session_record.h", 
  "libsignal-protocol-c/src/session_pre_key.h", 
  "libsignal-protocol-c/src/session_builder.h", 
  "libsignal-protocol-c/src/session_cipher.h", 
  "libsignal-protocol-c/src/key_helper.h", 
  "libsignal-protocol-c/src/sender_key.h", 
  "libsignal-protocol-c/src/sender_key_state.h", 
  "libsignal-protocol-c/src/sender_key_record.h", 
  "libsignal-protocol-c/src/group_session_builder.h", 
  "libsignal-protocol-c/src/group_cipher.h", 
  "libsignal-protocol-c/src/fingerprint.h"]

  s.xcconfig = { 'HEADER_SEARCH_PATHS' => '$(PODS_ROOT)/RNOMEMOCipher/src $(PODS_ROOT)/RNOMEMOCipher/src/curve25519 $(PODS_ROOT)/RNOMEMOCipher/src/curve25519/ed25519 $(PODS_ROOT)/RNOMEMOCipher/src/protobuf-c' }
  
  s.dependency "React"
  #s.dependency "others"

end

  