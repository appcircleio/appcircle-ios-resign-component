# frozen_string_literal: true

require 'openssl'
require 'cfpropertylist'

# .mobileprovision file parser
class MobileProvision
  def initialize(path)
    @path = path
  end

  def name
    mobileprovision['Name']
  end

  def app_name
    mobileprovision['AppIDName']
  end

  def decode(output)
    output = `security cms -D -i "#{@path}" > "#{output}"`
    raise "Decoding failed. Check logs for details \n\n #{output}" unless $CHILD_STATUS.success?
  end

  def bundle_id
    identifier = entitlements['application-identifier']
    identifier[/#{team_identifier}\.(.*)/, 1]
  end

  def app_identifier_prefix
    identifier = entitlements['application-identifier']
    return identifier[/(^[A-Z0-9]*)/, 1] if identifier

    app_prefixes = entitlements['ApplicationIdentifierPrefix']
    if app_prefixes
      puts "WARNING: extracted an app identifier prefix was not found in the profile's entitlements"
      app_prefixes[0]
    else
      puts "Can't extract App Identifier Prefix"
      nil
    end
  end

  def team_identifier_prefix
    identifier = entitlements['com.apple.developer.team-identifier']
    return identifier if identifier

    if team_identifier
      puts "WARNING: extracted an team identifier prefix was not found in the profile's entitlements"
      team_identifier[0]
    else
      puts "Can't extract Team Identifier Prefix"
      nil
    end
  end

  def type
    return 'Development' if development?
    return 'Ad Hoc' if adhoc?
    return 'AppStore' if appstore?
    return 'Enterprise' if enterprise?
  end

  def platforms
    return unless platforms = mobileprovision['Platform']

    platforms.map do |v|
      v = 'macOS' if v == 'OSX'
      v.downcase.to_sym
    end
  end

  def platform
    platforms[0]
  end

  def devices
    mobileprovision['ProvisionedDevices']
  end

  def team_identifier
    mobileprovision['TeamIdentifier']
  end

  def team_name
    mobileprovision['TeamName']
  end

  def profile_name
    mobileprovision['Name']
  end

  def created_date
    mobileprovision['CreationDate']
  end

  def expired_date
    mobileprovision['ExpirationDate']
  end

  def entitlements
    mobileprovision['Entitlements']
  end

  def developer_certs
    certs = mobileprovision['DeveloperCertificates']
    return if certs.empty?

    certs.each_with_object([]) do |cert, obj|
      obj << DeveloperCertificate.new(cert)
    end
  end

  # Detect is development type of mobileprovision
  #
  # related link: https://stackoverflow.com/questions/1003066/what-does-get-task-allow-do-in-xcode
  def development?
    case platform.downcase.to_sym
    when :ios
      entitlements['get-task-allow'] == true
    when :macos
      !devices.nil?
    else
      raise Error, "Not implement with platform: #{platform}"
    end
  end

  # Detect app store type
  #
  # related link: https://developer.apple.com/library/archive/qa/qa1830/_index.html
  def appstore?
    case platform.downcase.to_sym
    when :ios
      !development? && entitlements.key?('beta-reports-active')
    when :macos
      !development?
    else
      raise Error, "Not implement with platform: #{platform}"
    end
  end

  def adhoc?
    return false if platform == :macos # macOS no need adhoc

    !development? && !devices.nil?
  end

  def enterprise?
    return false if platform == :macos # macOS no need adhoc

    !development? && !adhoc? && !appstore?
  end
  alias inhouse? enterprise?

  # Enabled Capabilites
  #
  # Related link: https://developer.apple.com/support/app-capabilities/

  def capabilities
    {
      'com.apple.developer.networking.wifi-info' => 'Access WiFi Information',
      'com.apple.developer.devicecheck.appattest-environment' => 'App Attest',
      'com.apple.security.application-groups' => 'App Groups',
      'com.apple.developer.in-app-payments' => 'Apple Pay Payment Processing',
      'com.apple.developer.associated-domains' => 'Associated Domains',
      'com.apple.developer.authentication-services.autofill-credential-provider' => 'AutoFill Credential Provider',
      'com.apple.developer.ClassKit-environment' => 'ClassKit',
      'com.apple.developer.usernotifications.communication' => 'Communication Notifications',
      'com.apple.developer.networking.custom-protocol' => 'Custom Network Protocol',
      'com.apple.developer.default-data-protection' => 'Data Protection',
      'com.apple.developer.driverkit' => 'DriverKit for Development',
      'com.apple.developer.driverkit.allow-third-party-userclients' => 'DriverKit Allow Third Party UserClients',
      'com.apple.developer.driverkit.communicates-with-drivers' => 'DriverKit Communicates with Drivers',
      'com.apple.developer.driverkit.family.audio' => 'DriverKit Family Audio (development)',
      'com.apple.developer.driverkit.family.hid.device' => 'DriverKit Family HID Device (development)',
      'com.apple.developer.driverkit.family.hid.eventservice' => 'DriverKit Family HID EventService (development)',
      'com.apple.developer.driverkit.family.networking' => 'DriverKit Family Networking (development)',
      'com.apple.developer.driverkit.family.scsicontroller' => 'DriverKit Family SCSIController (development)',
      'com.apple.developer.driverkit.family.serial' => 'DriverKit Family Serial (development)',
      'com.apple.developer.driverkit.transport.hid' => 'DriverKit Transport HID (development)',
      'com.apple.developer.driverkit.transport.usb' => 'DriverKit USB Transport (development)',
      'com.apple.developer.kernel.extended-virtual-addressing' => 'Extended Virtual Address Space',
      'com.apple.developer.family-controls' => 'Family Controls',
      'com.apple.developer.fileprovider.testing-mode' => 'FileProvider TestingMode',
      'com.apple.developer.user-fonts' => 'Fonts',
      'com.apple.developer.game-center' => 'Game Center',
      'com.apple.developer.group-session' => 'Group Activities',
      'com.apple.developer.healthkit' => 'HealthKit',
      'com.apple.developer.healthkit.recalibrate-estimates' => 'HealthKit Estimate Recalibration',
      'com.apple.developer.healthkit.access' => 'HealthKit Access',
      'com.apple.developer.coremedia.hls.interstitial-preview' => 'HLS Interstitial Previews',
      'com.apple.developer.homekit' => 'HomeKit',
      'com.apple.developer.networking.HotspotConfiguration' => 'Hotspot',
      'com.apple.developer.icloud-services' => 'iCloud',
      'com.apple.developer.icloud-container-identifiers' => 'iCloud Container',
      'com.apple.InAppPurchase' => 'In-App Purchase',
      'com.apple.developer.kernel.increased-memory-limit' => 'Increased Memory Limit',
      'inter-app-audio' => 'Inter-App Audio',
      'com.apple.developer.coremedia.hls.low-latency' => 'Low Latency HLS',
      'com.apple.developer.maps' => 'Maps',
      'com.apple.developer.matter.allow-setup-payload' => 'Matter Allow Setup Payload',
      'com.apple.developer.associated-domains.mdm-managed' => 'MDM Managed Associated Domains',
      'com.apple.developer.media-device-discovery-extension' => 'Media Device Discovery',
      'com.apple.developer.shared-with-you.collaboration' => 'Messages Collaboration',
      'com.apple.developer.networking.multipath' => 'Multipath',
      'com.apple.developer.networking.networkextension' => 'Network Extensions',
      'com.apple.developer.nfc.readersession.formats' => 'NFC Tag Reading',
      'com.apple.developer.on-demand-install-capable' => 'On Demand Install Capable for App Clip Extensions',
      'com.apple.developer.networking.vpn.api' => 'Personal VPN',
      'aps-environment' => 'Push Notifications',
      'com.apple.developer.push-to-talk' => 'Push to Talk',
      'com.apple.developer.shared-with-you' => 'Shared with You',
      'com.apple.developer.applesignin' => 'Sign In with Apple',
      'com.apple.developer.siri' => 'SiriKit',
      'com.apple.developer.system-extension.install' => 'System Extension',
      'com.apple.developer.usernotifications.time-sensitive' => 'Time Sensitive Notifications',
      'com.apple.developer.user-management' => 'User Management',
      'com.apple.developer.pass-type-identifiers' => 'Wallet',
      'com.apple.developer.weatherkit' => 'WeatherKit',
      'com.apple.external-accessory.wireless-configuration' => 'Wireless Accessory Configuration'
    }
  end

  def enabled_cap
    result = []
    result << 'In-App Purchase' << 'GameKit' if adhoc? || appstore?
    entitlements.each do |key, _|
      result << capabilities[key]
    end
    result.compact.uniq
  end

  def enabled_capabilities
    capabilities = []
    capabilities << 'In-App Purchase' << 'GameKit' if adhoc? || appstore?

    entitlements.each do |key, _|
      case key
      when 'aps-environment'
        capabilities << 'Push Notifications'
      when 'com.apple.developer.applesignin'
        capabilities << 'Sign In with Apple'
      when 'com.apple.developer.siri'
        capabilities << 'SiriKit'
      when 'com.apple.security.application-groups'
        capabilities << 'App Groups'
      when 'com.apple.developer.associated-domains'
        capabilities << 'Associated Domains'
      when 'com.apple.developer.default-data-protection'
        capabilities << 'Data Protection'
      when 'com.apple.developer.networking.networkextension'
        capabilities << 'Network Extensions'
      when 'com.apple.developer.networking.vpn.api'
        capabilities << 'Personal VPN'
      when 'com.apple.developer.healthkit',
           'com.apple.developer.healthkit.access'
        capabilities << 'HealthKit' unless capabilities.include?('HealthKit')
      when 'com.apple.developer.icloud-services',
           'com.apple.developer.icloud-container-identifiers'
        capabilities << 'iCloud' unless capabilities.include?('iCloud')
      when 'com.apple.developer.in-app-payments'
        capabilities << 'Apple Pay'
      when 'com.apple.developer.homekit'
        capabilities << 'HomeKit'
      when 'com.apple.developer.user-fonts'
        capabilities << 'Fonts'
      when 'com.apple.developer.pass-type-identifiers'
        capabilities << 'Wallet'
      when 'com.apple.developer.shared-with-you'
        capabilities << 'Shared with You'
      when 'inter-app-audio'
        capabilities << 'Inter-App Audio'
      when 'com.apple.developer.networking.multipath'
        capabilities << 'Multipath'
      when 'com.apple.developer.authentication-services.autofill-credential-provider'
        capabilities << 'AutoFill Credential Provider'
      when 'com.apple.developer.networking.wifi-info'
        capabilities << 'Access WiFi Information'
      when 'com.apple.external-accessory.wireless-configuration'
        capabilities << 'Wireless Accessory Configuration'
      when 'com.apple.developer.kernel.extended-virtual-addressing'
        capabilities << 'Extended Virtual Address Space'
      when 'com.apple.developer.nfc.readersession.formats'
        capabilities << 'NFC Tag Reading'
      when 'com.apple.developer.ClassKit-environment'
        capabilities << 'ClassKit'
      when 'com.apple.developer.usernotifications.communication'
        capabilities << 'Communication Notifications'
      when 'com.apple.developer.networking.HotspotConfiguration'
        capabilities << 'Hotspot'
      when 'com.apple.developer.devicecheck.appattest-environment'
        capabilities << 'App Attest'
      when 'com.apple.developer.usernotifications.time-sensitive'
        capabilities << 'Time Sensitive Notifications'
      when 'com.apple.developer.group-session'
        capabilities << 'Group Activities'
      when 'com.apple.developer.family-controls'
        capabilities << 'Family Controls'
      when 'com.apple.developer.coremedia.hls.low-latency'
        capabilities << 'Low Latency HLS'
      when 'com.apple.developer.fileprovider.testing-mode'
        capabilities << 'FileProvider TestingMode'
      when 'com.apple.developer.healthkit.recalibrate-estimates'
        capabilities << 'Recalibrate Estimates'
      when 'com.apple.developer.weatherkit'
        capabilities << 'WeatherKit'
      when 'com.apple.developer.on-demand-install-capable'
        capabilities << 'On Demand Install Capable for App Clip Extensions'
      when 'com.apple.developer.associated-domains.mdm-managed'
        capabilities << 'MDM Managed Associated Domains'
      when 'com.apple.developer.user-management'
        capabilities << 'TV Services'
      when 'com.apple.developer.push-to-talk'
        capabilities << 'Push to Talk'
      when 'com.apple.developer.kernel.increased-memory-limit'
        capabilities << 'Increased Memory Limit'
      when 'com.apple.developer.driverkit.communicates-with-drivers'
        capabilities << 'Communicates with Drivers'
      when 'com.apple.developer.media-device-discovery-extension'
        capabilities << 'Media Device Discovery'
      # macOS Only
      when 'com.apple.developer.maps'
        capabilities << 'Maps'
      when 'com.apple.developer.system-extension.install'
        capabilities << 'System Extension'
      when 'com.apple.developer.driverkit'
        capabilities << 'DriverKit for Development'
      when 'com.apple.developer.driverkit.transport.usb'
        capabilities << 'DriverKit USB Transport (development)'
      when 'com.apple.developer.driverkit.family.scsicontroller'
        capabilities << 'DriverKit Family SCSIController (development)'
      when 'com.apple.developer.driverkit.family.serial'
        capabilities << 'DriverKit Family Serial (development)'
      when 'com.apple.developer.driverkit.family.networking'
        capabilities << 'DriverKit Family Networking (development)'
      when 'com.apple.developer.driverkit.family.hid.eventservice'
        capabilities << 'DriverKit Family HID EventService (development)'
      when 'com.apple.developer.driverkit.family.hid.device'
        capabilities << 'DriverKit Family HID Device (development)'
      when 'com.apple.developer.driverkit.transport.hid'
        capabilities << 'DriverKit Transport HID (development)'
      when 'com.apple.developer.driverkit.family.audio'
        capabilities << 'DriverKit Family Audio (development)'
      when 'com.apple.developer.driverkit.allow-third-party-userclients'
        capabilities << 'DriverKit Allow Third Party UserClients'
      when 'com.apple.developer.networking.custom-protocol'
        capabilities << 'Custom Network Protocol'
      end
    end

    capabilities
  end

  def empty?
    mobileprovision.nil?
  end

  def mobileprovision
    return @mobileprovision = nil unless File.exist?(@path)

    data = File.read(@path)
    data = strip_plist_wrapper(data) unless bplist?(data)
    list = CFPropertyList::List.new(data: data).value
    @mobileprovision = CFPropertyList.native_types(list)
  rescue CFFormatError
    @mobileprovision = nil
  end

  private

  def bplist?(raw)
    raw[0..5] == 'bplist'
  end

  def strip_plist_wrapper(raw)
    end_tag = '</plist>'
    start_point = raw.index('<?xml version=')
    end_point = raw.index(end_tag) + end_tag.size - 1
    raw[start_point..end_point]
  end

  # Developer Certificate
  class DeveloperCertificate
    attr_reader :raw

    def initialize(data)
      @raw = OpenSSL::X509::Certificate.new(data)
    end

    def name
      @raw.subject.to_a.find { |name, _, _| name == 'CN' }[1].force_encoding('UTF-8')
    end

    def created_date
      @raw.not_after
    end

    def signature
      OpenSSL::Digest::SHA1.new(@raw.to_der).to_s
    end

    def expired_date
      @raw.not_before
    end
  end
end
