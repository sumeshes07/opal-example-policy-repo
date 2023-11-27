package app.rbac


# By default, deny requests
default allow = false
#default user_has_tenant_access:=false

# check user exist or not
isUserExist = false if {
	not data.accessinfo.users[input.userId]
}

# check role exist or not
isRoleExist = false if {
	user:= data.accessinfo.users[input.userId]
	some roleId in user.roleIds
	not data.accessinfo.roles[roleId].permissionIds
}

# check permission exist or not
isPermissionExist = false if {
	roleIds:= data.accessinfo.users[input.userId].roleIds
	some roleId in roleIds
	permissionIds:= data.accessinfo.roles[roleId].permissionIds
    some permissionId in permissionIds
    not data.accessinfo.permissions[permissionId]
}

# Allow admins to do anything
allow {
	#user_has_tenant_access
    
	#fetching and assigning users
    user:=data.accessinfo.users[input.userId]
    
    #checking role exist for the current user
    #input.roleId==user.roleIds[_]
    
    # fetching the permission ids of role
    permissionIds:=data.accessinfo.roles[user.roleIds[_]].permissionIds
    
   	#print(permissionIds)
    
    #checking the user have access to a particular resource
    input.resource==data.accessinfo.permissions[permissionIds[_]].resource
    
    #checking the user have access to do a particular action on that resource
    input.action==data.accessinfo.permissions[permissionIds[_]].actions[_]
}