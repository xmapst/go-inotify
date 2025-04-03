//go:build linux

package inotify

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type IWatcher interface {
	WatchList() []string
	Add(path string) error
	Remove(path string) error
	Events() <-chan *Event
	Errors() <-chan error
	Close() error
}

const eventBufferSize = 4096 * (unix.SizeofInotifyEvent + unix.NAME_MAX + 1)

type sWatcher struct {
	eventChan chan *Event
	errorChan chan error

	fd          int
	inotifyFile *os.File
	watches     *watches

	done     chan struct{}
	doneMu   sync.Mutex
	doneResp chan struct{}

	cookies     [10]koekje
	cookieIndex uint8
	cookiesMu   sync.Mutex
}

func New() (IWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify init failed: %w", err)
	}

	w := &sWatcher{
		fd:          fd,
		inotifyFile: os.NewFile(uintptr(fd), ""),
		watches:     newWatches(),
		eventChan:   make(chan *Event, 65535),
		errorChan:   make(chan error, 1024),
		done:        make(chan struct{}),
		doneResp:    make(chan struct{}),
	}

	go w.eventLoop()
	return w, nil
}

func (w *sWatcher) sendEvent(e *Event) bool {
	select {
	case <-w.done:
		return false
	case w.eventChan <- e:
		return true
	}
}

func (w *sWatcher) sendError(err error) bool {
	if err == nil {
		return true
	}
	select {
	case <-w.done:
		return false
	case w.errorChan <- err:
		return true
	}
}

func (w *sWatcher) isClosed() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

func (w *sWatcher) Close() error {
	w.doneMu.Lock()
	if w.isClosed() {
		w.doneMu.Unlock()
		return nil
	}
	close(w.done)
	w.doneMu.Unlock()

	_ = unix.Close(w.fd)
	err := w.inotifyFile.Close()
	if err != nil {
		return err
	}
	<-w.doneResp
	return nil
}

func (w *sWatcher) Events() <-chan *Event {
	return w.eventChan
}

func (w *sWatcher) Errors() <-chan error {
	return w.errorChan
}

func (w *sWatcher) Add(path string) error {
	if w.isClosed() {
		return fmt.Errorf("watcher is closed")
	}
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("get abs path failed: %w", err)
	}
	return w.addWatchRecursive(absPath, false)
}

func (w *sWatcher) addWatchRecursive(path string, sedEvent bool) error {
	return filepath.Walk(path, func(root string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !fi.IsDir() {
			if root == path {
				return fmt.Errorf("not a directory: %q", path)
			}
			return nil
		}
		if sedEvent {
			w.sendEvent(&Event{
				Type:  "CREATE",
				Path:  root,
				IsDir: true,
			})
		}
		return w.register(root, uint32(unix.IN_ALL_EVENTS))
	})
}

func (w *sWatcher) register(path string, flags uint32) error {
	return w.watches.updatePath(path, func(existing *watch) (*watch, error) {
		if existing != nil {
			flags |= existing.flags | unix.IN_MASK_ADD
		}
		wd, err := unix.InotifyAddWatch(w.fd, path, flags)
		if wd == -1 {
			return nil, err
		}
		if existing == nil {
			return &watch{
				wd:    uint32(wd),
				path:  path,
				flags: flags,
			}, nil
		}
		existing.wd = uint32(wd)
		existing.flags = flags
		return existing, nil
	})
}

func (w *sWatcher) Remove(path string) error {
	if w.isClosed() {
		return nil
	}
	return w.remove(filepath.Clean(path))
}

func (w *sWatcher) remove(name string) error {
	wds, err := w.watches.removePath(name)
	if err != nil {
		return err
	}

	for _, wd := range wds {
		_, _, err = unix.RawSyscall(syscall.SYS_INOTIFY_RM_WATCH, uintptr(w.fd), uintptr(wd), 0)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *sWatcher) WatchList() []string {
	if w.isClosed() {
		return nil
	}

	entries := make([]string, 0, w.watches.len())
	w.watches.mu.RLock()
	for pathname := range w.watches.path {
		entries = append(entries, pathname)
	}
	w.watches.mu.RUnlock()

	return entries
}

func (w *sWatcher) eventLoop() {
	defer func() {
		recover()
		close(w.doneResp)
		close(w.errorChan)
		close(w.eventChan)
	}()
	var buf [eventBufferSize]byte
	for {
		if w.isClosed() {
			return
		}
		n, err := w.inotifyFile.Read(buf[:])
		switch {
		case errors.Is(errors.Unwrap(err), os.ErrClosed):
			return
		case err != nil:
			if !w.sendError(err) {
				return
			}
			continue
		}

		if n < unix.SizeofInotifyEvent {
			var errno error
			if n == 0 {
				errno = io.EOF // If EOF is received. This should really never happen.
			} else if n < 0 {
				errno = err // If an error occurred while reading.
			} else {
				errno = errors.New("notify: short read in readEvents()") // Read was too short.
			}
			if !w.sendError(errno) {
				return
			}
			continue
		}
		w.parseEvents(n, buf)
	}
}

func (w *sWatcher) parseEvents(n int, data [eventBufferSize]byte) {
	var offset uint32
	for offset <= uint32(n-unix.SizeofInotifyEvent) {
		var (
			// Point "raw" to the event in the buffer
			raw     = (*unix.InotifyEvent)(unsafe.Pointer(&data[offset]))
			mask    = raw.Mask
			nameLen = raw.Len
			// Move to the next event in the buffer
			next = func() { offset += unix.SizeofInotifyEvent + nameLen }
		)

		if mask&unix.IN_Q_OVERFLOW != 0 {
			if !w.sendError(fmt.Errorf("queue or buffer overflow")) {
				return
			}
		}

		_watch := w.watches.byWd(uint32(raw.Wd))
		if _watch == nil {
			next()
			continue
		}

		name := _watch.path
		if nameLen > 0 {
			/// Point "bytes" at the first byte of the filename
			_bytes := (*[unix.PathMax]byte)(unsafe.Pointer(&data[offset+unix.SizeofInotifyEvent]))[:nameLen:nameLen]
			/// The filename is padded with NULL bytes. TrimRight() gets rid of those.
			name += "/" + strings.TrimRight(string(_bytes[0:nameLen]), "\000")
		}

		if mask&unix.IN_IGNORED != 0 {
			next()
			continue
		}

		if mask&unix.IN_DELETE_SELF == unix.IN_DELETE_SELF {
			w.watches.remove(_watch.wd)
		}

		if mask&unix.IN_MOVE_SELF == unix.IN_MOVE_SELF {
			next()
			continue
		}

		if mask&unix.IN_DELETE_SELF != 0 {
			if _, ok := w.watches.path[filepath.Dir(_watch.path)]; ok {
				next()
				continue
			}
		}

		event := w.newEvent(name, mask, raw.Cookie)
		if event.IsDir && strings.Contains(event.Type, "CREATE") {
			err := w.addWatchRecursive(event.Path, true)
			if !w.sendError(err) {
				return
			}
			if event.renamedFrom != "" {
				w.watches.mu.Lock()
				for k, ww := range w.watches.wd {
					if k == _watch.wd || ww.path == event.Path {
						continue
					}
					if strings.HasPrefix(ww.path, event.renamedFrom) {
						ww.path = strings.Replace(ww.path, event.renamedFrom, event.Path, 1)
						w.watches.wd[k] = ww
					}
				}
				w.watches.mu.Unlock()
			}
		}

		if !w.sendEvent(event) {
			return
		}
		next()
	}
}

func (w *sWatcher) timespecToTime(ts syscall.Timespec) time.Time {
	if ts.Sec == 0 && ts.Nsec == 0 {
		return time.Time{}
	}
	return time.Unix(ts.Sec, ts.Nsec)
}

func (w *sWatcher) newEvent(name string, mask, cookie uint32) *Event {
	var _mask uint32
	e := &Event{
		Path:  name,
		IsDir: mask&unix.IN_ISDIR == unix.IN_ISDIR,
	}
	if mask&unix.IN_CREATE == unix.IN_CREATE || mask&unix.IN_MOVED_TO == unix.IN_MOVED_TO {
		_mask |= unix.IN_CREATE
	}
	if mask&unix.IN_DELETE_SELF == unix.IN_DELETE_SELF || mask&unix.IN_DELETE == unix.IN_DELETE {
		_mask |= unix.IN_DELETE
	}
	if mask&unix.IN_MODIFY == unix.IN_MODIFY {
		_mask |= unix.IN_MODIFY
	}
	if mask&unix.IN_OPEN == unix.IN_OPEN {
		_mask |= unix.IN_OPEN
	}
	if mask&unix.IN_ACCESS == unix.IN_ACCESS {
		_mask |= unix.IN_ACCESS
	}
	if mask&unix.IN_CLOSE_WRITE == unix.IN_CLOSE_WRITE {
		_mask |= unix.IN_CLOSE
	}
	if mask&unix.IN_CLOSE_NOWRITE == unix.IN_CLOSE_NOWRITE {
		_mask |= unix.IN_CLOSE
	}
	if mask&unix.IN_MOVE_SELF == unix.IN_MOVE_SELF || mask&unix.IN_MOVED_FROM == unix.IN_MOVED_FROM {
		_mask |= unix.IN_MOVE
	}
	if mask&unix.IN_ATTRIB == unix.IN_ATTRIB {
		_mask |= unix.IN_ATTRIB
	}

	if cookie != 0 {
		if mask&unix.IN_MOVED_FROM == unix.IN_MOVED_FROM {
			w.cookiesMu.Lock()
			w.cookies[w.cookieIndex] = koekje{cookie: cookie, path: e.Path}
			w.cookieIndex++
			if w.cookieIndex > 9 {
				w.cookieIndex = 0
			}
			w.cookiesMu.Unlock()
		} else if mask&unix.IN_MOVED_TO == unix.IN_MOVED_TO {
			w.cookiesMu.Lock()
			var prev string
			for _, c := range w.cookies {
				if c.cookie == cookie {
					prev = c.path
					break
				}
			}
			w.cookiesMu.Unlock()
			e.renamedFrom = prev
		}
	}
	var res []string
	for k, v := range eventBits {
		if _mask&k == _mask {
			res = append(res, v)
		}
	}
	if len(res) == 0 {
		e.Type = "UNKNOWN"
	}
	e.Type = strings.Join(res, "|")
	return e
}
