package app.rbac

import future.keywords.contains
import future.keywords.if
import future.keywords.in


# By default, deny requests
default allow = false
#default user_has_tenant_access:=false

# check user exist or not
isUserExist = false if {
	not data.accessinfo.users[input.userId]
}

# check role exist or not
#isRoleExist = false if {
#	user:= data.accessinfo.users[input.userId]
#    print(user.roleIds)
#	some roleId in user.roleIds
#	not data.accessinfo.roles[roleId].permissionIds
#}

# check permission exist or not
#isPermissionExist = false if {
#	roleIds:= data.accessinfo.users[input.userId].roleIds
#	some roleId in roleIds
#	permissionIds:= data.accessinfo.roles[roleId].permissionIds
#    some permissionId in permissionIds
#    not data.accessinfo.permissions[permissionId]
#}

# Allow admins to do anything
allow {
	#user_has_tenant_access
    
	#fetching and assigning users
    user:= data.accessinfo.users[input.userId]
    #print(user)
    #checking role exist for the current user
    #input.roleId==user.roleIds[_]
    
    # fetching the permission ids of role
    some roleId in user.roleIds
    permissionIds:= data.accessinfo.roles[roleId].permissionIds
    
   	print(permissionIds)
    
    #checking the user have access to a particular resource
    some permissionId in permissionIds
    input.resource == data.accessinfo.permissions[permissionId].resource[_]
    
    
    #checking the user have access to do a particular action on that resource
    some permission in permissionIds
    input.action == data.accessinfo.permissions[permission].actions[_]
}