package inotify

import (
	"golang.org/x/sys/unix"
)

type (
	koekje struct {
		cookie uint32
		path   string
	}
	Event struct {
		Type        string `json:"type"`
		Path        string `json:"path"`
		IsDir       bool   `json:"is_dir"`
		renamedFrom string
	}
)

var eventBits = map[uint32]string{
	unix.IN_ACCESS: "ACCESS",
	unix.IN_ATTRIB: "ATTRIB",
	unix.IN_CLOSE:  "CLOSE",
	unix.IN_CREATE: "CREATE",
	unix.IN_DELETE: "DELETE",
	unix.IN_MODIFY: "MODIFY",
	unix.IN_MOVE:   "MOVE",
	unix.IN_OPEN:   "OPEN",
}
