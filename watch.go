package inotify

import (
	"fmt"
	"path/filepath"
	"strings"
)

type (
	watches struct {
		wd   map[uint32]*watch // wd → watch
		path map[string]uint32 // pathname → wd
	}
	watch struct {
		wd    uint32 // Watch descriptor (as returned by the inotify_add_watch() syscall)
		flags int    // inotify flags of this watch (see inotify(7) for the list of valid flags)
		path  string // Watch path.
		mark  Op
	}
)

func newWatches() *watches {
	return &watches{
		wd:   make(map[uint32]*watch),
		path: make(map[string]uint32),
	}
}

func (w *watches) byPath(path string) *watch { return w.wd[w.path[path]] }
func (w *watches) byWd(wd uint32) *watch     { return w.wd[wd] }
func (w *watches) len() int                  { return len(w.wd) }
func (w *watches) add(ww *watch)             { w.wd[ww.wd] = ww; w.path[ww.path] = ww.wd }
func (w *watches) remove(watch *watch)       { delete(w.path, watch.path); delete(w.wd, watch.wd) }

func (w *watches) removePath(path string) ([]uint32, error) {
	path = filepath.Clean(path)
	wd, ok := w.path[path]
	if !ok {
		return nil, fmt.Errorf("can't remove non-existent watch: %s", path)
	}
	delete(w.path, path)
	delete(w.wd, wd)

	wds := make([]uint32, 0, 8)
	wds = append(wds, wd)
	for p, rwd := range w.path {
		if strings.HasPrefix(p, path) {
			delete(w.path, p)
			delete(w.wd, rwd)
			wds = append(wds, rwd)
		}
	}
	return wds, nil
}

func (w *watches) updatePath(path string, f func(*watch) (*watch, error)) error {
	var existing *watch
	wd, ok := w.path[path]
	if ok {
		existing = w.wd[wd]
	}

	upd, err := f(existing)
	if err != nil {
		return err
	}
	if upd != nil {
		w.wd[upd.wd] = upd
		w.path[upd.path] = upd.wd

		if upd.wd != wd {
			delete(w.wd, wd)
		}
	}

	return nil
}
