#!/usr/bin/env python3
'''
We discovered a heap-based buffer overflow in Sudo
(https://www.sudo.ws/). This vulnerability:

- is exploitable by any local user (normal users and system users,
  sudoers and non-sudoers), without authentication (i.e., the attacker
  does not need to know the user's password);

- was introduced in July 2011 (commit 8255ed69), and affects all legacy
  versions from 1.8.2 to 1.8.31p2 and all stable versions from 1.9.0 to
  1.9.5p1, in their default configuration.

We developed three different exploits for this vulnerability, and
obtained full root privileges on Ubuntu 20.04 (Sudo 1.8.31), Debian 10
(Sudo 1.8.27), and Fedora 33 (Sudo 1.9.2). Other operating systems and
distributions are probably also exploitable.
'''

'''
The second crash that caught our attention is:

------------------------------------------------------------------------
Program received signal SIGSEGV, Segmentation fault.

0x00007f6bf9c294ee in nss_load_library (ni=ni@entry=0x55cf1a1dd040) at nsswitch.c:344

=> 0x7f6bf9c294ee <nss_load_library+46>:        cmpq   $0x0,0x8(%rbx)

rbx            0x41414141414141    18367622009667905
------------------------------------------------------------------------

The glibc's function nss_load_library() crashed (at line 344) because we
overwrote the pointer "library", a member of a heap-based struct
service_user:

------------------------------------------------------------------------
327 static int
328 nss_load_library (service_user *ni)
329 {
330   if (ni->library == NULL)
331     {
...
338       ni->library = nss_new_service (service_table ?: &default_table,
339                                      ni->name);
...
342     }
343 
344   if (ni->library->lib_handle == NULL)
345     {
346       /* Load the shared library.  */
347       size_t shlen = (7 + strlen (ni->name) + 3
348                       + strlen (__nss_shlib_revision) + 1);
349       int saved_errno = errno;
350       char shlib_name[shlen];
351 
352       /* Construct shared object name.  */
353       __stpcpy (__stpcpy (__stpcpy (__stpcpy (shlib_name,
354                                               "libnss_"),
355                                     ni->name),
356                           ".so"),
357                 __nss_shlib_revision);
358 
359       ni->library->lib_handle = __libc_dlopen (shlib_name);
------------------------------------------------------------------------
