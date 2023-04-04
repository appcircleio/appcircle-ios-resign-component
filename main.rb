# frozen_string_literal: true

require 'English'
require 'shellwords'
require 'colored'
require 'json'
require 'fileutils'
require 'nokogiri'
require 'openssl'
require_relative 'provisioning_parser'

def find_resign_path
  sh_script_path = "#{File.expand_path(File.dirname(__FILE__))}/resign.sh"
  "bash #{sh_script_path}"
end

def valid_xml?(xml_string)
  Nokogiri::XML(xml_string)
  true
rescue Nokogiri::XML::SyntaxError
  false
end

def create_provisioning_options(provisioning_profiles)
  provisioning_profiles.map do |app_id, app_id_prov|
    if app_id_prov
      app_id_prov = File.expand_path(app_id_prov)
    else
      app_id = File.expand_path(app_id)
    end
    "-p #{[app_id, app_id_prov].compact.map(&:shellescape).join('=')}"
  end.join(' ')
end

def create_entitlements_options(targets)
  targets.map do |target|
    filepath = File.join(ENV['AC_TEMP_DIR'], "#{target['BundleId']}.xml")
    if !File.exist?(filepath) && target['Entitlements']
      if valid_xml?(target['Entitlements'])
        File.write(filepath, target['Entitlements'])
        "-e #{filepath.shellescape}"
      else
        puts "Target #{target['BundleId']} doesn't have valid entitlements"
        nil
      end
    end
  end.compact.join(' ')
end

def get_provisioning_profiles
  if ENV['AC_PROVISIONING_PROFILES'].nil? || ENV['AC_PROVISIONING_PROFILES'] == ''
    puts 'AC_PROVISIONING_PROFILES does not exist.'
    []
  else
    provisioning_profiles = ENV['AC_PROVISIONING_PROFILES']
    provisioning_profiles.split('|').map do |path|
      converted = "#{path}.mobileprovision"
      puts "Copying #{path} -> #{converted}"
      FileUtils.cp(path, converted)
      converted
    end
  end
end

def bundle_ids
  if ENV['AC_BUNDLE_IDENTIFIERS'].nil? || ENV['AC_BUNDLE_IDENTIFIERS'] == ''
    puts 'AC_BUNDLE_IDENTIFIERS does not exist.'
    []
  else
    bundle_ids = ENV['AC_BUNDLE_IDENTIFIERS']
    bundle_ids.split('|')
  end
end

def resign(ipa, signing_identity, provisioning_profiles, entitlements, version, display_name, short_version,
           bundle_version, new_bundle_id, use_app_entitlements)
  resign_path = find_resign_path

  provisioning_profiles = [provisioning_profiles] unless provisioning_profiles.is_a?(Enumerable)

  provisioning_options = create_provisioning_options(provisioning_profiles)
  version = "-n #{version}" if version
  display_name = "-d #{display_name.shellescape}" if display_name
  short_version = "--short-version #{short_version}" if short_version
  bundle_version = "--bundle-version #{bundle_version}" if bundle_version
  bundle_id = "-b '#{new_bundle_id}'" if new_bundle_id
  use_app_entitlements_flag = '--use-app-entitlements' if use_app_entitlements
  output_dir = ENV['AC_OUTPUT_DIR']
  ouutput_file =  File.join(output_dir,ipa)

  command = [
    resign_path,
    ipa.shellescape,
    signing_identity.shellescape,
    provisioning_options, # we are aleady shellescaping this above, when we create the provisioning_options from the provisioning_profiles
    entitlements,
    version,
    display_name,
    short_version,
    bundle_version,
    use_app_entitlements_flag,
    bundle_id,
    output_file # Output path must always be last argument
  ].join(' ')

  puts(command.magenta)
  puts(`#{command}`)

  if $CHILD_STATUS.to_i.zero?
    puts "Successfully signed #{ipa}!"
    FileUtils.cp(ipa, File.join((ENV['AC_OUTPUT_DIR']).to_s))
    true
  else
    puts("Something went wrong while code signing #{ipa}")
    false
  end
end

ipa_url = ENV['AC_RESIGN_IPA_URL']
ipa = ENV['AC_RESIGN_FILENAME']
`curl -o "./#{ipa}" -k "#{ipa_url}"`
puts 'DEBUG'
puts 'File Header'
puts `xxd -l 32 #{ipa}`
puts `ls "#{File.expand_path(File.dirname(__FILE__))}"`

targets_json = ENV['AC_RESIGN_TARGETS']
targets = JSON.parse(File.read(targets_json))
main_target = targets.first
puts "Main Target: #{main_target}"
provisioning_profiles = get_provisioning_profiles
first_provision = MobileProvision.new(provisioning_profiles.first)
# Extract the first certificate
certificate = first_provision.developer_certs[0]
signing_identity = certificate.signature
signing_name = certificate.name
puts "Name: #{signing_name} SHA-1: #{signing_identity}"

provisioning_profile = Hash[bundle_ids.zip(provisioning_profiles)]
entitlements = create_entitlements_options(targets)

version = nil
display_name = main_target['Display']
short_version = main_target['Version']
bundle_version = main_target['BuildNumber']
new_bundle_id = main_target['BundleId']
use_app_entitlements = main_target['UseOriginal']

puts "Entitlements #{entitlements}"
puts "Display Name #{display_name}"
puts "Single Version #{version}"

puts "Version #{short_version}"
puts "Build Number #{bundle_version}"
puts "Bundle Id #{new_bundle_id}"
puts "Use Original #{use_app_entitlements}"

resign(ipa,
       signing_identity,
       provisioning_profile,
       entitlements,
       version,
       display_name,
       short_version,
       bundle_version,
       new_bundle_id,
       use_app_entitlements)
       