require 'net/ldap'

# Naughty bits of active directory ldap queries
class LdapFluff::ActiveDirectory::MemberService < LdapFluff::GenericMemberService

  def initialize(ldap, config)
    @attr_login = (config.attr_login || 'samaccountname')
    super
  end

  # get a list [] of ldap groups for a given user
  # in active directory, this means a recursive lookup
  def find_user_groups(uid)
    data = find_user(uid)
    _groups_from_ldap_data(data.first)
  end
  
  def find_user_service(uid)
      data = find_user(uid)
      _service_from_ldap_data(data.first)
  end
  
  def find_user_service_id(uid)
      data = find_user(uid)
      _service_id_from_ldap_data(data.first)
  end
  
  def find_user_name_direction(uid)
      data = find_user(uid)
      _name_direction_from_ldap_data(data.first)
  end
  
  def find_user_name_dga(uid)
      data = find_user(uid)
      _name_dga_from_ldap_data(data.first)
  end
  
  def find_user_manager_id(uid)
      data = find_user(uid)
      _manager_id_from_ldap_data(data.first)
  end
  
   def _manager_id_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:managerID]
    end
    data
  end
  
  def find_user_director_id(uid)
      data = find_user(uid)
      _director_id_from_ldap_data(data.first)
  end
  
   def _director_id_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:departmentHeadID]
    end
    data
  end
  
  def _name_dga_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:description]
    end
    data
  end
  
  def _name_direction_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:description]
    end
    data
  end
   
  def _service_id_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:serviceNumber]
    end
    data
  end
  
  def _service_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:department]
    end
    data
  end
  
  def find_user_matricule(uid)
      data = find_user(uid)
      _matricule_from_ldap_data(data.first)
  end
  
   def _matricule_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:cn]
    end
    data
  end
  
   def find_user_mail(uid)
      data = find_user(uid)
      _mail_from_ldap_data(data.first)
  end
  
   def _mail_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:mail]
    end
    data
  end
  
  def find_user_firstName(uid)
      data = find_user(uid)
      _firstName_from_ldap_data(data.first)
  end
  
   def _firstName_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:givenName]
    end
    data
  end
  
  def find_user_lastName(uid)
      data = find_user(uid)
      _lastName_from_ldap_data(data.first)
  end
  
   def _lastName_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:sn]
    end
    data
  end
  
  def find_user_middleName(uid)
      data = find_user(uid)
      _middleName_from_ldap_data(data.first)
  end

  def find_user_street(uid)
      data = find_user(uid)
      _street_from_ldap_data(data.first)
  end

   def _middleName_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:middleName]
    end
    data
  end

   def _street_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:street]
    end
    data
  end

  def find_user_division(uid)
      data = find_user(uid)
      _division_from_ldap_data(data.first)
  end
  
  def _division_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:division]
    end
    data
  end
  
  # return the :memberof attrs + parents, recursively
  def _groups_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:memberof]
      # first_level     = payload[:description]
      # total_groups, _ = _walk_group_ancestry(first_level, first_level)
      # data            = (get_groups(first_level + total_groups)).uniq 
    end
    data
  end

  # recursively loop over the parent list
  def _walk_group_ancestry(group_dns = [], known_groups = [])
    set = []
    group_dns.each do |group_dn|
      search = @ldap.search(:base => group_dn, :scope => Net::LDAP::SearchScope_BaseObject, :attributes => ['memberof'])
      if !search.nil? && !search.first.nil?
        groups                       = search.first[:memberof] - known_groups
        known_groups                += groups
        next_level, new_known_groups = _walk_group_ancestry(groups, known_groups)
        set                         += next_level
        set                         += groups
        known_groups                += next_level
      end
    end
    [set, known_groups]
  end

  def class_filter
    Net::LDAP::Filter.eq("objectclass", "group")
  end

  class UIDNotFoundException < LdapFluff::Error
  end

  class GIDNotFoundException < LdapFluff::Error
  end
end
