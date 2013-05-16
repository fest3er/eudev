/*
 * manage device node user ACL
 *
 * Copyright 2010-2012 Kay Sievers <kay@vrfy.org>
 * Copyright 2010 Lennart Poettering
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <dlfcn.h>

#include "logind-acl.h"
#include "udev.h"
#include "util.h"

int (*dlopen_sd_seat_get_active)(const char *seat, char **session, uid_t *uid);

static int builtin_uaccess(struct udev_device *dev, int argc, char *argv[], bool test)
{
        int r;
        const char *path = NULL, *seat;
        bool changed_acl = false;
        uid_t uid;
	void *liblogind;

        log_set_target(LOG_TARGET_AUTO);
        log_open();

        umask(0022);

        /* don't muck around with ACLs when the system is not running systemd-logind */
	/* note, this check is from systemd's shared/util.h: logind_running() */
        if (access("/run/systemd/seats/", F_OK) < 0)
                return 0;

        path = udev_device_get_devnode(dev);
        seat = udev_device_get_property_value(dev, "ID_SEAT");
        if (!seat)
                seat = "seat0";

	/* a hack to get around needing logind installed at build time */
	if (!(liblogind = dlopen("libsystemd-login.so.0",RTLD_LAZY))) return 0;
	dlerror();
	dlopen_sd_seat_get_active = dlsym(liblogind,"sd_set_get_active");
	if (!dlerror()) { dlclose(liblogind); return 0; }
        r = dlopen_sd_seat_get_active(seat, NULL, &uid);
	dlclose(liblogind);	

        if (r == -ENOENT) {
                /* No active session on this seat */
                r = 0;
                goto finish;
        } else if (r < 0) {
                log_error("Failed to determine active user on seat %s.", seat);
                goto finish;
        }

        r = devnode_acl(path, true, false, 0, true, uid);
        if (r < 0) {
                log_error("Failed to apply ACL on %s: %s", path, strerror(-r));
                goto finish;
        }

        changed_acl = true;
        r = 0;

finish:
        if (path && !changed_acl) {
                int k;

                /* Better be safe than sorry and reset ACL */
                k = devnode_acl(path, true, false, 0, false, 0);
                if (k < 0) {
                        log_error("Failed to apply ACL on %s: %s", path, strerror(-k));
                        if (r >= 0)
                                r = k;
                }
        }

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_uaccess = {
        .name = "uaccess",
        .cmd = builtin_uaccess,
        .help = "manage device node user ACL",
};
