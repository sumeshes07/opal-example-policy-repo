package app.generic

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# By default, deny requests
default allowgeneric = false

allowgeneric if {
actions := data.accessinfo.defaultPermissions[input.resource].actions
input.action == actions[_]
}