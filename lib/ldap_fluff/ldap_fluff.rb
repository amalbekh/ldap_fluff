require 'rubygems'
require 'net/ldap'

class LdapFluff
  attr_accessor :ldap, :instrumentation_service

  def initialize(config = {})
    config = LdapFluff::Config.new(config)
    case config.server_type
    when :posix
      @ldap = Posix.new(config)
    when :active_directory
      @ldap = ActiveDirectory.new(config)
    when :free_ipa
      @ldap = FreeIPA.new(config)
    else
      raise 'unknown server_type'
    end
    @instrumentation_service = config.instrumentation_service
  end

  def authenticate?(uid, password)
    instrument('authenticate.ldap_fluff', :uid => uid) do |payload|
      if password.nil? || password.empty?
        false
      else
        !!@ldap.bind?(uid, password)
      end
    end
  end

  def test
    instrument('test.ldap_fluff') do |payload|
      @ldap.ldap.open {}
    end
  end

  # return a list[] of users for a given gid
  def user_list(gid)
    instrument('user_list.ldap_fluff', :gid => gid) do |payload|
      @ldap.users_for_gid(gid)
    end
  end

  # return a list[] of groups for a given uid
  def group_list(uid)
    instrument('group_list.ldap_fluff', :uid => uid) do |payload|
      @ldap.groups_for_uid(uid)
    end
  end
  
  def service_list(uid)
    instrument('service_list.ldap_fluff', :uid => uid) do |payload|
      @ldap.service_for_uid(uid)
    end
  end
  
   def service_id(uid)
    instrument('service_id.ldap_fluff', :uid => uid) do |payload|
      @ldap.service_id_for_uid(uid)
    end
  end
  
  def name_direction(uid)
    instrument('name_direction.ldap_fluff', :uid => uid) do |payload|
      @ldap.name_direction_for_uid(uid)
    end
  end
  
   def name_dga(uid)
    instrument('name_dga.ldap_fluff', :uid => uid) do |payload|
      @ldap.name_dga_for_uid(uid)
    end
  end
  
  def manager_id(uid)
    instrument('manager_id.ldap_fluff', :uid => uid) do |payload|
      @ldap.manager_id_for_uid(uid)
    end
  end
  
  def director_id(uid)
    instrument('director_id.ldap_fluff', :uid => uid) do |payload|
      @ldap.director_id_for_uid(uid)
    end
  end
  
  def matricule(uid)
    instrument('matricule.ldap_fluff', :uid => uid) do |payload|
      @ldap.matricule_for_uid(uid)
    end
  end
  
  def mail(uid)
    instrument('mail.ldap_fluff', :uid => uid) do |payload|
      @ldap.mail_for_uid(uid)
    end
  end
  
  def division(uid)
    instrument('division.ldap_fluff', :uid => uid) do |payload|
      @ldap.division_for_uid(uid)
    end
  end
  
  def firstName(uid)
    instrument('firstName.ldap_fluff', :uid => uid) do |payload|
      @ldap.firstName_for_uid(uid)
    end
  end
  
  def lastName(uid)
    instrument('lastName.ldap_fluff', :uid => uid) do |payload|
      @ldap.lastName_for_uid(uid)
    end
  end
  
  def middleName(uid)
    instrument('middleName.ldap_fluff', :uid => uid) do |payload|
      @ldap.middleName_for_uid(uid)
    end
  end

  def street(uid)
    instrument('street.ldap_fluff', :uid => uid) do |payload|
      @ldap.street_for_uid(uid)
    end
  end

  def telephoneNumber(uid)
    instrument('telephoneNumber.ldap_fluff', :uid => uid) do |payload|
      @ldap.telephoneNumber_for_uid(uid)
    end
  end

  def postalCode(uid)
    instrument('postalCode.ldap_fluff', :uid => uid) do |payload|
      @ldap.postalCode_for_uid(uid)
    end
  end

  # return true if a user is in all of the groups
  # in grouplist
  def is_in_groups?(uid, grouplist)
    instrument('is_in_groups?.ldap_fluff', :uid => uid, :grouplist => grouplist) do |payload|
      @ldap.is_in_groups(uid, grouplist, true)
    end
  end

  # return true if uid exists
  def valid_user?(uid)
    instrument('valid_user?.ldap_fluff', :uid => uid) do |payload|
      @ldap.user_exists? uid
    end
  end

  # return true if group exists
  def valid_group?(gid)
    instrument('valid_group?.ldap_fluff', :gid => gid) do |payload|
      @ldap.group_exists? gid
    end
  end

  # return ldap entry
  def find_user(uid)
    instrument('find_user.ldap_fluff', :uid => uid) do |payload|
      @ldap.member_service.find_user(uid)
    end
  end

  # return ldap entry
  def find_group(gid)
    instrument('find_group.ldap_fluff', :gid => gid) do |payload|
      @ldap.member_service.find_group(gid)
    end
  end

  private

  def instrument(event, payload = {})
    payload = (payload || {}).dup
    if instrumentation_service
      instrumentation_service.instrument(event, payload) do |payload|
        payload[:result] = yield(payload) if block_given?
      end
    else
      yield(payload) if block_given?
    end
  end
end
