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
  
  def find_user_name_service(uid)
      data = find_user(uid)
      _name_service_from_ldap_data(data.first)
  end
  
  def find_user_name_direction(uid)
      data = find_user(uid)
      _name_direction_from_ldap_data(data.first)
  end
  
  def _name_direction_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:description]
    end
    data
  end
   
  def _name_service_from_ldap_data(payload)
    data = []
    if !payload.nil?
      data = payload[:service]
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
