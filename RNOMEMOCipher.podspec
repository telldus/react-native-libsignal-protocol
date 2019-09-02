
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
  s.source       = { :git => "https://github.com/telldus/react-native-omemo-cipher.git", :tag => "ios-fix" }
  s.source_files  = "ios/*.{h,m}", "ios/libsignal-protocol-c/*"
  s.public_header_files = ["ios/libsignal-protocol-c/src/signal_protocol.h", "ios/libsignal-protocol-c/src/signal_protocol_types.h", "ios/libsignal-protocol-c/src/curve.h", "ios/libsignal-protocol-c/src/hkdf.h", "ios/libsignal-protocol-c/src/ratchet.h", "ios/libsignal-protocol-c/src/protocol.h", "ios/libsignal-protocol-c/src/session_state.h", "ios/libsignal-protocol-c/src/session_record.h", "ios/libsignal-protocol-c/src/session_pre_key.h", "ios/libsignal-protocol-c/src/session_builder.h", "ios/libsignal-protocol-c/src/session_cipher.h", "ios/libsignal-protocol-c/src/key_helper.h", "ios/libsignal-protocol-c/src/sender_key.h", "ios/libsignal-protocol-c/src/sender_key_state.h", "ios/libsignal-protocol-c/src/sender_key_record.h", "ios/libsignal-protocol-c/src/group_session_builder.h", "ios/libsignal-protocol-c/src/group_cipher.h", "ios/libsignal-protocol-c/src/fingerprint.h"]
  
  s.dependency "React"
  #s.dependency "others"

end

  