
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
  s.source_files  = "ios/*.{h,m}"
  s.dependency "React"
  #s.dependency "others"

end

  