# frozen_string_literal: true

require_relative 'lib/ml_kem/version'

Gem::Specification.new do |spec|
  spec.name = 'ml_kem'
  spec.version = MLKem::VERSION
  spec.authors = ['Bharat Singh Parihar']
  spec.email = ['404ghost.2@gmail.com']

  spec.summary = 'Pure-Ruby ML-KEM (FIPS 203) — KAT-verified post-quantum key encapsulation'
  spec.description = 'ML-KEM-512/768/1024 (formerly Kyber) implemented in pure Ruby with zero ' \
                     'runtime dependencies, including the Keccak/SHAKE core. Verified against ' \
                     'final FIPS 203 known-answer tests and the C2SP/CCTV vector suite. ' \
                     'A KAT-verified reference: correct and portable, not side-channel hardened.'
  spec.homepage = 'https://github.com/bharat3645/ml-kem-rb'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.0'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri'] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir['lib/**/*.rb'] + %w[README.md CHANGELOG.md LICENSE]
  spec.require_paths = ['lib']
end
