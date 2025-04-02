//go:build linux

package inotify

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type sWatcher struct {
	fd        int
	epollFd   int
	watchLock sync.Mutex
	watchMap  map[int32]string
	renameMap map[uint32]*Event
	eventChan chan *Event
	errors    chan error
	done      chan struct{}
	// 用于防抖动
	debounceMu       sync.Mutex
	debounceMap      map[string]*time.Timer
	debounceDuration time.Duration
}

func New() (IWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify init failed: %w", err)
	}

	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("epoll create failed: %w", err)
	}

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
	}
	if err = unix.EpollCtl(epollFd, unix.EPOLL_CTL_ADD, fd, &event); err != nil {
		_ = unix.Close(fd)
		_ = unix.Close(epollFd)
		return nil, fmt.Errorf("epoll ctl failed: %w", err)
	}

	w := &sWatcher{
		fd:               fd,
		epollFd:          epollFd,
		watchMap:         make(map[int32]string),
		renameMap:        make(map[uint32]*Event),
		eventChan:        make(chan *Event, 65535),
		errors:           make(chan error, 1024),
		done:             make(chan struct{}),
		debounceMap:      make(map[string]*time.Timer),
		debounceDuration: 300 * time.Millisecond,
	}

	go w.eventLoop()
	return w, nil
}

func (w *sWatcher) Events() <-chan *Event {
	return w.eventChan
}

func (w *sWatcher) Errors() <-chan error {
	return w.errors
}

func (w *sWatcher) Remove(path string) error {
	w.watchLock.Lock()
	defer w.watchLock.Unlock()
	path = filepath.Clean(path)

	for _wd, _path := range w.watchMap {
		if !strings.HasPrefix(_path, path) {
			continue
		}
		delete(w.watchMap, _wd)
		_, _, e1 := unix.RawSyscall(syscall.SYS_INOTIFY_RM_WATCH, uintptr(w.fd), uintptr(_wd), 0)
		if e1 != 0 {
			return fmt.Errorf("inotify rm watch failed: %w", e1)
		}
		return nil
	}
	return nil
}

func (w *sWatcher) Add(path string) error {
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("get abs path failed: %w", err)
	}
	return w.addWatchRecursive(absPath)
}

func (w *sWatcher) addWatchRecursive(path string) error {
	return filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fi.IsDir() {
			return w.addDir(p)
		}
		return nil
	})
}

func (w *sWatcher) addDir(path string) error {
	w.watchLock.Lock()
	defer w.watchLock.Unlock()

	path = filepath.Clean(path)
	for _, _path := range w.watchMap {
		if _path == path {
			return nil
		}
	}

	wd, err := unix.InotifyAddWatch(w.fd, path, unix.IN_ALL_EVENTS)
	if err != nil {
		return fmt.Errorf("inotify add watch failed: %w", err)
	}
	w.watchMap[int32(wd)] = path

	return nil
}

func (w *sWatcher) getPath(wd int32) (string, bool) {
	w.watchLock.Lock()
	defer w.watchLock.Unlock()
	path, ok := w.watchMap[wd]
	return path, ok
}

func (w *sWatcher) eventLoop() {
	defer func() {
		recover()
		_ = unix.Close(w.fd)
		_ = unix.Close(w.epollFd)
	}()

	events := make([]unix.EpollEvent, 1)
	for {
		select {
		case <-w.done:
			return
		default:
			n, err := unix.EpollWait(w.epollFd, events, -1)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				w.errors <- fmt.Errorf("epoll wait error: %w", err)
				return
			}

			if n <= 0 {
				continue
			}
			var buf = make([]byte, eventBufferSize)
			readBytes, err := unix.Read(w.fd, buf)
			if err != nil && !errors.Is(err, unix.EAGAIN) {
				w.errors <- fmt.Errorf("read error: %w", err)
				continue
			}

			if readBytes > 0 {
				w.parseEvents(buf[:readBytes])
			}
		}
	}
}

func (w *sWatcher) parseEvents(data []byte) {
	offset := 0
	for offset < len(data) {
		rawEvent := (*unix.InotifyEvent)(unsafe.Pointer(&data[offset]))
		offset += unix.SizeofInotifyEvent

		nameBytes := data[offset : offset+int(rawEvent.Len)]
		name := string(bytes.TrimRight(nameBytes, "\x00"))
		offset += int(rawEvent.Len)

		basePath, ok := w.getPath(rawEvent.Wd)
		if !ok {
			continue
		}

		fullPath := filepath.Join(basePath, name)
		isDir := (rawEvent.Mask & unix.IN_ISDIR) != 0

		event := &Event{
			mask:  rawEvent.Mask,
			Path:  fullPath,
			IsDir: isDir,
		}
		event.Type = event.typeStr()
		if strings.Contains(event.Type, "MOVED_FROM") {
			w.renameMap[rawEvent.Cookie] = event
		} else if strings.Contains(event.Type, "MOVED_TO") {
			if fromEvent, exists := w.renameMap[rawEvent.Cookie]; exists {
				event.Rename = &Rename{
					From: fromEvent.Path,
					To:   fullPath,
				}
				delete(w.renameMap, rawEvent.Cookie)
			}
		}

		if isDir {
			if strings.Contains(event.Type, "CREATE") {
				_ = w.addWatchRecursive(fullPath)
			}
		}
		info, err := os.Stat(fullPath)
		if err != nil {
			if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file or directory") {
				event.Type = "DELETE"
				w.watchLock.Lock()
				for _wd, _path := range w.watchMap {
					if _path == fullPath {
						delete(w.watchMap, _wd)
					}
				}
				w.watchLock.Unlock()
			}
		}
		if info != nil {
			statTtime := info.Sys().(*syscall.Stat_t)
			event.CreateTime = w.timespecToTime(statTtime.Ctim)
			event.ModifyTime = w.timespecToTime(statTtime.Mtim)
			if !event.CreateTime.IsZero() && time.Now().UTC().Sub(event.CreateTime).Seconds() < 1 {
				event.Type = "CREATE"
			}
		}

		if event.Type != "" {
			w.handleEventWithDebounce(event)
		}
	}
}

func (w *sWatcher) timespecToTime(ts syscall.Timespec) time.Time {
	if ts.Sec == 0 && ts.Nsec == 0 {
		return time.Time{}
	}
	return time.Unix(ts.Sec, ts.Nsec)
}

func (w *sWatcher) handleEventWithDebounce(event *Event) {
	// 对创建事件进行防抖动处理
	if event.Type == "CREATE" {
		w.debounceMu.Lock()
		defer w.debounceMu.Unlock()

		key := event.Path
		// 如果存在现有定时器，则重置
		if timer, exists := w.debounceMap[key]; exists {
			timer.Stop()
			delete(w.debounceMap, key)
		}

		// 创建新定时器延迟发送事件
		timer := time.AfterFunc(w.debounceDuration, func() {
			w.debounceMu.Lock()
			delete(w.debounceMap, key)
			w.debounceMu.Unlock()
			w.eventChan <- event
		})
		w.debounceMap[key] = timer
	} else {
		// 其他事件类型直接发送
		w.eventChan <- event
	}
}

func (w *sWatcher) Close() {
	close(w.done)

	// 停止所有防抖动定时器
	w.debounceMu.Lock()
	for _, timer := range w.debounceMap {
		timer.Stop()
	}
	w.debounceMap = make(map[string]*time.Timer) // 清空防抖动映射
	w.debounceMu.Unlock()

	close(w.eventChan)
	close(w.errors)
}
