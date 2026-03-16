package headerinclude

// stdHeaders is the curated set of standard C and C++ library header names.
// Includes from this set are filtered out as they are not third-party dependencies.
var stdHeaders = map[string]struct{}{
	// C standard library
	"assert.h": {}, "complex.h": {}, "ctype.h": {}, "errno.h": {}, "fenv.h": {},
	"float.h": {}, "inttypes.h": {}, "iso646.h": {}, "limits.h": {}, "locale.h": {},
	"math.h": {}, "setjmp.h": {}, "signal.h": {}, "stdalign.h": {}, "stdarg.h": {},
	"stdatomic.h": {}, "stdbool.h": {}, "stddef.h": {}, "stdint.h": {}, "stdio.h": {},
	"stdlib.h": {}, "stdnoreturn.h": {}, "string.h": {}, "tgmath.h": {}, "threads.h": {},
	"time.h": {}, "uchar.h": {}, "wchar.h": {}, "wctype.h": {},

	// POSIX / system headers
	"unistd.h": {}, "fcntl.h": {}, "sys/types.h": {}, "sys/stat.h": {}, "sys/socket.h": {},
	"sys/wait.h": {}, "sys/time.h": {}, "sys/mman.h": {}, "sys/ioctl.h": {},
	"pthread.h": {}, "dirent.h": {}, "dlfcn.h": {}, "netdb.h": {},
	"netinet/in.h": {}, "arpa/inet.h": {}, "poll.h": {}, "semaphore.h": {},

	// C++ standard library — C wrappers
	"cassert": {}, "ccomplex": {}, "cctype": {}, "cerrno": {}, "cfenv": {},
	"cfloat": {}, "cinttypes": {}, "ciso646": {}, "climits": {}, "clocale": {},
	"cmath": {}, "csetjmp": {}, "csignal": {}, "cstdalign": {}, "cstdarg": {},
	"cstdbool": {}, "cstddef": {}, "cstdint": {}, "cstdio": {}, "cstdlib": {},
	"cstring": {}, "ctgmath": {}, "ctime": {}, "cuchar": {}, "cwchar": {}, "cwctype": {},

	// C++ standard library — containers & algorithms
	"algorithm": {}, "array": {}, "bitset": {}, "deque": {}, "forward_list": {},
	"list": {}, "map": {}, "queue": {}, "set": {}, "stack": {}, "unordered_map": {},
	"unordered_set": {}, "vector": {},

	// C++ standard library — strings & streams
	"fstream": {}, "iomanip": {}, "ios": {}, "iosfwd": {}, "iostream": {},
	"istream": {}, "ostream": {}, "sstream": {}, "streambuf": {}, "string": {},
	"string_view": {}, "strstream": {},

	// C++ standard library — utilities
	"any": {}, "chrono": {}, "codecvt": {}, "complex": {},
	"condition_variable": {}, "exception": {}, "execution": {}, "filesystem": {},
	"functional": {}, "future": {}, "initializer_list": {}, "iterator": {},
	"limits": {}, "locale": {}, "memory": {}, "memory_resource": {}, "mutex": {},
	"new": {}, "numeric": {}, "optional": {}, "random": {}, "ratio": {},
	"regex": {}, "scoped_allocator": {}, "shared_mutex": {}, "span": {},
	"stdexcept": {}, "stop_token": {}, "system_error": {}, "thread": {},
	"tuple": {}, "type_traits": {}, "typeindex": {}, "typeinfo": {},
	"utility": {}, "valarray": {}, "variant": {}, "version": {},

	// C++ standard library — atomics & concurrency
	"atomic": {}, "barrier": {}, "latch": {}, "semaphore": {},

	// C++17 additions
	"charconv": {},

	// C++20 additions
	"bit": {}, "compare": {}, "concepts": {}, "coroutine": {}, "format": {},
	"numbers": {}, "ranges": {}, "source_location": {}, "syncstream": {},

	// C++23 additions
	"expected": {}, "flat_map": {}, "flat_set": {}, "generator": {},
	"mdspan": {}, "print": {}, "spanstream": {}, "stacktrace": {},

	// Windows SDK headers (commonly seen in cross-platform projects)
	"windows.h": {}, "winsock2.h": {}, "ws2tcpip.h": {}, "windef.h": {},
	"winbase.h": {}, "winnt.h": {}, "tchar.h": {},
}
