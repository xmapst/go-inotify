//go:build linux

package inotify

import (
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type IWatcher interface {
	Add(path string) error
	Remove(path string) error
	Events() <-chan *Event
	Errors() <-chan error
	Close()
}

const eventBufferSize = 4096 * (unix.SizeofInotifyEvent + unix.NAME_MAX + 1)

type Event struct {
	mask       uint32
	Type       string    `json:"type"`
	Path       string    `json:"path"`
	IsDir      bool      `json:"is_dir"`
	Rename     *Rename   `json:"rename,omitempty"`
	CreateTime time.Time `json:"create_time,omitempty"`
	ModifyTime time.Time `json:"modify_time,omitempty"`
}

func (e *Event) String() string {
	return e.Path + ":" + e.typeStr()
}
func (e *Event) typeStr() string {
	var res []string
	for k, v := range eventBits {
		if e.mask&k != 0 {
			res = append(res, v)
		}
	}
	if len(res) == 0 {
		return "UNKNOWN"
	}

	for i := 0; i < len(res); i++ {
		for j := i + 1; j < len(res); j++ {
			if res[i] == res[j] {
				res = append(res[:j], res[j+1:]...)
				j--
			}
		}
	}
	return strings.Join(res, "|")
}

type Rename struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

var eventBits = map[uint32]string{
	unix.IN_ACCESS:        "ACCESS",
	unix.IN_ATTRIB:        "ATTRIB",
	unix.IN_CLOSE:         "CLOSE",
	unix.IN_CLOSE_NOWRITE: "CLOSE",
	unix.IN_CLOSE_WRITE:   "CLOSE",
	unix.IN_CREATE:        "CREATE",
	unix.IN_DELETE:        "DELETE",
	unix.IN_DELETE_SELF:   "DELETE",
	unix.IN_MODIFY:        "MODIFY",
	unix.IN_MOVED_FROM:    "MOVED",
	unix.IN_MOVED_TO:      "MOVED",
	unix.IN_MOVE_SELF:     "MOVED",
	unix.IN_OPEN:          "OPEN",
}
