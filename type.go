package inotify

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

type (
	Op     uint32
	koekje struct {
		cookie uint32
		path   string
	}
	Event struct {
		Type        Op     `json:"type"`
		Path        string `json:"path"`
		IsDir       bool   `json:"is_dir"`
		RenamedFrom string `json:"renamed_from,omitempty"`
	}
)

const (
	ACCESS Op = unix.IN_ACCESS
	ATTRIB Op = unix.IN_ATTRIB
	CLOSE  Op = unix.IN_CLOSE
	CREATE Op = unix.IN_CREATE
	DELETE Op = unix.IN_DELETE
	MODIFY Op = unix.IN_MODIFY
	MOVE   Op = unix.IN_MOVE
	OPEN   Op = unix.IN_OPEN
)

var eventBits = map[Op]string{
	ACCESS: "ACCESS",
	ATTRIB: "ATTRIB",
	CLOSE:  "CLOSE",
	CREATE: "CREATE",
	DELETE: "DELETE",
	MODIFY: "MODIFY",
	MOVE:   "MOVE",
	OPEN:   "OPEN",
}

func (o Op) String() string {
	var res []string
	for k, v := range eventBits {
		if o&k == o {
			res = append(res, v)
		}
	}
	if len(res) == 0 {
		return "UNKNOWN"
	}
	return strings.Join(res, "|")
}

func (o Op) MarshalJSON() ([]byte, error) {
	return []byte(`"` + o.String() + `"`), nil
}

func (o Op) MarshalText() ([]byte, error) {
	return []byte(o.String()), nil
}

func (e *Event) String() string {
	return fmt.Sprintf("%s:%s(%v)", e.Path, e.Type, e.IsDir)
}

func (e *Event) Has(op Op) bool {
	return e.Type&op != 0
}
