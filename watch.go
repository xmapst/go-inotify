package inotify

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

type (
	watches struct {
		mu   sync.RWMutex
		wd   map[uint32]*watch // wd → watch
		path map[string]uint32 // pathname → wd
	}
	watch struct {
		wd    uint32 // Watch descriptor (as returned by the inotify_add_watch() syscall)
		flags uint32 // inotify flags of this watch (see inotify(7) for the list of valid flags)
		path  string // Watch path.
	}
)

func newWatches() *watches {
	return &watches{
		wd:   make(map[uint32]*watch),
		path: make(map[string]uint32),
	}
}

func (w *watches) len() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.wd)
}

func (w *watches) remove(wd uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_watch := w.wd[wd] // Could have had Remove() called. See #616.
	if _watch == nil {
		return
	}
	delete(w.path, _watch.path)
	delete(w.wd, wd)
}

func (w *watches) removePath(path string) ([]uint32, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

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

func (w *watches) byPath(path string) *watch {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.wd[w.path[path]]
}

func (w *watches) byWd(wd uint32) *watch {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.wd[wd]
}

func (w *watches) updatePath(path string, f func(*watch) (*watch, error)) error {
	w.mu.Lock()
	defer w.mu.Unlock()

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
