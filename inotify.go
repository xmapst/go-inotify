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
	AddWith(path string, flag Op) error
	Remove(path string) error
	Events() <-chan *Event
	Errors() <-chan error
	Close() error
}

const eventBufferSize = 4096 * (unix.SizeofInotifyEvent + unix.NAME_MAX + 1)

type sWatcher struct {
	mu        sync.Mutex
	eventChan chan *Event
	errorChan chan error

	fd          int
	inotifyFile *os.File
	watches     *watches

	done     chan struct{}
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

	go w.readEvents()
	return w, nil
}

func (w *sWatcher) sendEvent(e *Event) bool {
	if e == nil {
		return true
	}
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
	w.mu.Lock()
	if w.isClosed() {
		w.mu.Unlock()
		return nil
	}
	close(w.done)
	w.mu.Unlock()

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
	return w.AddWith(path, ALL_EVENTS)
}

func (w *sWatcher) AddWith(path string, mark Op) error {
	if w.isClosed() {
		return fmt.Errorf("watcher is closed")
	}
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("get abs path failed: %w", err)
	}
	// required type, recursive directories required
	var _flags = unix.IN_ALL_EVENTS | unix.IN_DONT_FOLLOW | unix.IN_IGNORED | unix.IN_UNMOUNT

	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addWatchRecursive(absPath, mark, _flags, false)
}

func (w *sWatcher) addWatchRecursive(path string, mark Op, flags int, sedEvent bool) error {
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
		// 判断mark是否为ALL_EVENTS或CREATE
		if sedEvent && (mark&CREATE == CREATE || mark == ALL_EVENTS) {
			w.sendEvent(&Event{
				Type:  CREATE,
				Path:  root,
				IsDir: true,
			})
		}
		return w.register(root, mark, flags)
	})
}

func (w *sWatcher) register(path string, mark Op, flags int) error {
	return w.watches.updatePath(path, func(existing *watch) (*watch, error) {
		if existing != nil {
			flags |= existing.flags | unix.IN_MASK_ADD
		}
		wd, err := unix.InotifyAddWatch(w.fd, path, uint32(flags))
		if wd == -1 {
			return nil, err
		}
		if existing == nil {
			return &watch{
				wd:    uint32(wd),
				path:  path,
				flags: flags,
				mark:  mark,
			}, nil
		}
		existing.wd = uint32(wd)
		existing.flags = flags
		existing.mark = mark
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
	w.mu.Lock()
	defer w.mu.Unlock()
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

	w.mu.Lock()
	defer w.mu.Unlock()
	entries := make([]string, 0, w.watches.len())
	for pathname := range w.watches.path {
		entries = append(entries, pathname)
	}

	return entries
}

func (w *sWatcher) readEvents() {
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
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			if !w.sendError(err) {
				return
			}
			continue
		}

		if n < unix.SizeofInotifyEvent {
			err = errors.New("notify: short read in readEvents()") // Read was too short.
			if n == 0 {
				err = io.EOF // If EOF is received. This should really never happen.
			}
			if !w.sendError(err) {
				return
			}
			continue
		}

		var offset uint32
		for offset <= uint32(n-unix.SizeofInotifyEvent) {
			// Point to the event in the buffer.
			inEvent := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))

			if inEvent.Mask&unix.IN_Q_OVERFLOW != 0 {
				if !w.sendError(fmt.Errorf("queue or buffer overflow")) {
					return
				}
			}

			ev, ok := w.handleEvent(inEvent, &buf, offset)
			if !ok {
				return
			}
			if !w.sendEvent(ev) {
				return
			}

			// Move to the next event in the buffer
			offset += unix.SizeofInotifyEvent + inEvent.Len
		}
	}
}

func (w *sWatcher) handleEvent(inEvent *unix.InotifyEvent, buf *[eventBufferSize]byte, offset uint32) (*Event, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	_watch := w.watches.byWd(uint32(inEvent.Wd))
	if _watch == nil {
		return nil, true
	}

	var (
		name    = _watch.path
		nameLen = inEvent.Len
	)
	if nameLen > 0 {
		/// Point "bytes" at the first byte of the filename
		bb := *buf
		bytes := (*[unix.PathMax]byte)(unsafe.Pointer(&bb[offset+unix.SizeofInotifyEvent]))[:nameLen:nameLen]
		/// The filename is padded with NULL bytes. TrimRight() gets rid of those.
		name += "/" + strings.TrimRight(string(bytes[0:nameLen]), "\x00")
	}

	if inEvent.Mask&unix.IN_IGNORED != 0 || inEvent.Mask&unix.IN_UNMOUNT != 0 {
		w.watches.remove(_watch)
		return nil, true
	}

	// inotify will automatically remove the watch on deletes; just need
	// to clean our state here.
	if inEvent.Mask&unix.IN_DELETE_SELF == unix.IN_DELETE_SELF {
		w.watches.remove(_watch)
	}

	// Skip if we're watching both this path and the parent; the parent will
	// already send a delete so no need to do it twice.
	if inEvent.Mask&unix.IN_DELETE_SELF != 0 {
		_, ok := w.watches.path[filepath.Dir(_watch.path)]
		if ok {
			return nil, true
		}
	}

	ev := w.newEvent(name, inEvent.Mask, inEvent.Cookie)

	if ev.IsDir && ev.Has(CREATE) {
		// mkdir -p create chain directory, recursive watch it.
		err := w.addWatchRecursive(ev.Path, _watch.mark, _watch.flags, true)
		if !w.sendError(err) {
			return nil, false
		}

		// This was a directory rename, so we need to update all the
		// children.
		//
		// TODO: this is of course pretty slow; we should use a better data
		// structure for storing all of this, e.g. store children in the
		// watch. I have some code for this in my kqueue refactor we can use
		// in the future. For now I'm okay with this as it's not publicly
		// available. Correctness first, performance second.
		if ev.RenamedFrom != "" {
			for k, ww := range w.watches.wd {
				if k == _watch.wd || ww.path == ev.Path {
					continue
				}
				if strings.HasPrefix(ww.path, ev.RenamedFrom) {
					ww.path = strings.Replace(ww.path, ev.RenamedFrom, ev.Path, 1)
					w.watches.wd[k] = ww
				}
			}
		}
	}
	if _watch.mark != ALL_EVENTS && !ev.Has(_watch.mark) {
		return nil, true
	}
	return ev, true
}

func (w *sWatcher) timespecToTime(ts syscall.Timespec) time.Time {
	if ts.Sec == 0 && ts.Nsec == 0 {
		return time.Time{}
	}
	return time.Unix(ts.Sec, ts.Nsec)
}

func (w *sWatcher) newEvent(name string, mask, cookie uint32) *Event {
	e := &Event{
		Path:  name,
		IsDir: mask&unix.IN_ISDIR == unix.IN_ISDIR,
	}
	if mask&unix.IN_CREATE == unix.IN_CREATE || mask&unix.IN_MOVED_TO == unix.IN_MOVED_TO {
		e.Type |= CREATE
	}
	if mask&unix.IN_DELETE_SELF == unix.IN_DELETE_SELF || mask&unix.IN_DELETE == unix.IN_DELETE {
		e.Type |= DELETE
	}
	if mask&unix.IN_MODIFY == unix.IN_MODIFY {
		e.Type |= MODIFY
	}
	if mask&unix.IN_OPEN == unix.IN_OPEN {
		e.Type |= OPEN
	}
	if mask&unix.IN_ACCESS == unix.IN_ACCESS {
		e.Type |= unix.IN_ACCESS
	}
	if mask&unix.IN_CLOSE_WRITE == unix.IN_CLOSE_WRITE {
		e.Type |= CLOSE
	}
	if mask&unix.IN_CLOSE_NOWRITE == unix.IN_CLOSE_NOWRITE {
		e.Type |= CLOSE
	}
	if mask&unix.IN_MOVE_SELF == unix.IN_MOVE_SELF || mask&unix.IN_MOVED_FROM == unix.IN_MOVED_FROM {
		e.Type |= MOVE
	}
	if mask&unix.IN_ATTRIB == unix.IN_ATTRIB {
		e.Type |= ATTRIB
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
			e.RenamedFrom = prev
		}
	}
	return e
}
