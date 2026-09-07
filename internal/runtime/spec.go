package runtime

import (
	"bufio"
	"fmt"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"niflhel/internal/api"
	"niflhel/internal/fsutil"
	"strconv"
	"strings"
)

func User(root, user string) (specs.User, error) {
	var out specs.User
	if user == "" {
		return out, nil
	}
	u, g, hasGroup := strings.Cut(user, ":")
	n, e := strconv.ParseUint(u, 10, 32)
	if e == nil {
		out.UID = uint32(n)
	}
	passwd, e2 := fsutil.OpenRootPath(root, "etc/passwd")
	if e2 == nil {
		defer passwd.Close()
		s := bufio.NewScanner(passwd)
		for s.Scan() {
			p := strings.Split(s.Text(), ":")
			if len(p) < 4 {
				continue
			}
			uid, ue := strconv.ParseUint(p[2], 10, 32)
			gid, ge := strconv.ParseUint(p[3], 10, 32)
			if ue != nil || ge != nil {
				continue
			}
			if p[0] == u || (e == nil && uint32(uid) == out.UID) {
				out.UID = uint32(uid)
				out.GID = uint32(gid)
				e = nil
				break
			}
		}
	}
	if e != nil {
		return out, fmt.Errorf("user %q not found in container", u)
	}
	if hasGroup {
		n, e = strconv.ParseUint(g, 10, 32)
		if e == nil {
			out.GID = uint32(n)
		} else {
			f, err := fsutil.OpenRootPath(root, "etc/group")
			if err != nil {
				return out, err
			}
			defer f.Close()
			scan := bufio.NewScanner(f)
			found := false
			for scan.Scan() {
				p := strings.Split(scan.Text(), ":")
				if len(p) >= 3 && p[0] == g {
					n, e = strconv.ParseUint(p[2], 10, 32)
					if e == nil {
						out.GID = uint32(n)
						found = true
						break
					}
				}
			}
			if !found {
				return out, fmt.Errorf("group %q not found", g)
			}
		}
	}
	return out, nil
}
func Build(s api.Sandbox, root, netns string) (*specs.Spec, error) {
	user, e := User(root, s.Process.User)
	if e != nil {
		return nil, e
	}
	memory := s.Spec.Memory
	quota := int64(s.Spec.CPUs) * 100000
	period := uint64(100000)
	caps := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_AUDIT_WRITE", "CAP_SETFCAP"}
	p := &specs.Process{Args: s.Process.Args, Env: s.Process.Env, Cwd: s.Process.Cwd, User: user, Terminal: s.Spec.TTY, NoNewPrivileges: true, Capabilities: &specs.LinuxCapabilities{Bounding: caps, Effective: caps, Permitted: caps}, Rlimits: []specs.POSIXRlimit{{Type: "RLIMIT_NOFILE", Hard: 65536, Soft: 65536}}}
	ns := []specs.LinuxNamespace{{Type: specs.PIDNamespace}, {Type: specs.MountNamespace}, {Type: specs.IPCNamespace}, {Type: specs.UTSNamespace}, {Type: specs.CgroupNamespace}, {Type: specs.NetworkNamespace, Path: netns}}
	if netns == "" {
		ns[len(ns)-1].Path = ""
	}
	mounts := []specs.Mount{{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}}, {Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}}, {Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"}}, {Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}}, {Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}}, {Destination: "/etc/resolv.conf", Type: "bind", Source: "/run/niflhel/resolv.conf", Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}}}
	for i, m := range s.Spec.Mounts {
		opts := []string{"bind", "nosuid", "nodev"}
		if m.ReadOnly {
			opts = append(opts, "ro")
		}
		mounts = append(mounts, specs.Mount{Destination: m.Target, Source: fmt.Sprintf("/run/niflhel/volumes/%d", i), Type: "bind", Options: opts})
	}
	// Default-deny syscall filtering; no mount, module, keyring, bpf, perf,
	// ptrace, or AF_VSOCK access is available to the workload.
	calls := strings.Fields("accept accept4 access alarm arch_prctl bind brk capget capset chdir chmod chown chown32 clock_getres clock_gettime clock_nanosleep clone clone3 close close_range connect copy_file_range creat dup dup2 dup3 epoll_create epoll_create1 epoll_ctl epoll_pwait epoll_pwait2 epoll_wait eventfd eventfd2 execve execveat exit exit_group faccessat faccessat2 fadvise64 fallocate fanotify_mark fchdir fchmod fchmodat fchown fchownat fcntl fdatasync fgetxattr flistxattr flock fork fremovexattr fsetxattr fstat fstatfs fsync ftruncate futex futex_waitv getcpu getcwd getdents getdents64 getegid geteuid getgid getgroups getitimer getpeername getpgid getpgrp getpid getppid getpriority getrandom getresgid getresuid getrlimit getrusage getsid getsockname getsockopt gettid gettimeofday getuid getxattr inotify_add_watch inotify_init inotify_init1 inotify_rm_watch ioctl kill lchown lgetxattr link linkat listen listxattr llistxattr lremovexattr lseek lsetxattr lstat madvise membarrier memfd_create mincore mkdir mkdirat mlock mlock2 mlockall mmap mprotect mremap msync munlock munlockall munmap nanosleep newfstatat open openat openat2 pause pipe pipe2 poll ppoll prctl pread64 preadv preadv2 prlimit64 pselect6 pwrite64 pwritev pwritev2 read readahead readlink readlinkat readv recvfrom recvmmsg recvmsg rename renameat renameat2 restart_syscall rmdir rseq rt_sigaction rt_sigpending rt_sigprocmask rt_sigqueueinfo rt_sigreturn rt_sigsuspend rt_sigtimedwait rt_tgsigqueueinfo sched_getaffinity sched_getparam sched_getscheduler sched_get_priority_max sched_get_priority_min sched_rr_get_interval sched_setaffinity sched_yield select sendfile sendmmsg sendmsg sendto setfsgid setfsuid setgid setgroups setitimer setpgid setpriority setregid setresgid setresuid setreuid setrlimit setsid setsockopt set_tid_address set_robust_list setuid shutdown sigaltstack signalfd signalfd4 socketpair splice stat statfs statx symlink symlinkat sync sync_file_range syncfs sysinfo tee tgkill time timer_create timer_delete timer_getoverrun timer_gettime timer_settime timerfd_create timerfd_gettime timerfd_settime times tkill truncate umask uname unlink unlinkat utime utimensat utimes vfork vmsplice wait4 waitid write writev")
	errno := uint(1)
	filter := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &errno, Architectures: []specs.Arch{specs.ArchX86_64}, Syscalls: []specs.LinuxSyscall{{Names: calls, Action: specs.ActAllow}}}
	for _, family := range []uint64{1, 2, 10} {
		filter.Syscalls = append(filter.Syscalls, specs.LinuxSyscall{Names: []string{"socket"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: family, Op: specs.OpEqualTo}}})
	}
	return &specs.Spec{Version: "1.2.1", Process: p, Root: &specs.Root{Path: root, Readonly: s.Spec.ReadOnly}, Hostname: s.Name, Mounts: mounts, Linux: &specs.Linux{Namespaces: ns, CgroupsPath: "/niflhel/app", Resources: &specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: &memory}, CPU: &specs.LinuxCPU{Quota: &quota, Period: &period}, Pids: &specs.LinuxPids{Limit: i64(s.Spec.PidsLimit)}, Devices: []specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}, {Allow: true, Type: "c", Major: i64(1), Minor: i64(3), Access: "rwm"}, {Allow: true, Type: "c", Major: i64(1), Minor: i64(5), Access: "rwm"}, {Allow: true, Type: "c", Major: i64(1), Minor: i64(7), Access: "rwm"}, {Allow: true, Type: "c", Major: i64(1), Minor: i64(8), Access: "rwm"}, {Allow: true, Type: "c", Major: i64(1), Minor: i64(9), Access: "rwm"}, {Allow: true, Type: "c", Major: i64(5), Minor: nil, Access: "rwm"}, {Allow: true, Type: "c", Major: i64(136), Minor: nil, Access: "rwm"}}}, MaskedPaths: []string{"/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/sched_debug", "/sys/firmware"}, ReadonlyPaths: []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}, Seccomp: filter}}, nil
}
func i64(n int64) *int64 { return &n }
