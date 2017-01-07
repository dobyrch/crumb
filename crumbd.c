#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <sqlite3.h>

#define DELETED " (deleted)"

static void store_event(int fd, sqlite3 *db)
{
	const struct fanotify_event_metadata *m;
	struct fanotify_event_metadata buf[4096];
	ssize_t len;
	char path1[PATH_MAX], path2[PATH_MAX], prog[PATH_MAX];
	ssize_t path_len1, path_len2;
	char procfd_path[PATH_MAX];
	char procexe_path[PATH_MAX];
	struct fanotify_response response;

	for (;;) {

		len = read(fd, (void *) &buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		if (len <= 0)
			break;

		for (m = buf; FAN_EVENT_OK(m, len); m = FAN_EVENT_NEXT(m, len)) {

			if (m->vers != FANOTIFY_METADATA_VERSION) {
				fprintf(stderr, "Mismatch of fanotify metadata version.\n");
				exit(EXIT_FAILURE);
			}

			if (m->fd < 0)
				continue;

			snprintf(procfd_path, sizeof(procfd_path),
					"/proc/self/fd/%d", m->fd);
			path_len1 = readlink(procfd_path, path1,
					sizeof(path1) - 1);
			if (path_len1 < 0) {
				perror("readlink");
				exit(EXIT_FAILURE);
			}

			path1[path_len1] = '\0';
			fprintf(stderr, "File %s", path1);


			snprintf(procexe_path, sizeof(procexe_path),
					"/proc/%d/exe", m->pid);
			path_len2 = readlink(procexe_path, path2,
					sizeof(path2) - 1);
			if (path_len2 != -1) {
				path2[path_len2] = '\0';
				fprintf(stderr, " [%s]", path2);
			}
			fprintf(stderr, "\n");

			close(m->fd);

			if (strstr(path1, DELETED) || strstr(path2, DELETED) ||
				path1[0] == '\0' || path2[0] == '\0')
				continue;

			sqlite3_stmt *statement = NULL;
			const char *tail;

			int r;
			r = sqlite3_prepare_v2(db,
				"insert or ignore into "
				"paths (path, exe) "
				"values (?, ?) ",
				100, // nicer way of reliably getting length
				&statement,
				&tail);
			//fprintf(stderr, "TAIL: %s\n", tail);
			//fprintf(stderr, "prepare: %d\n", r);



			r = sqlite3_bind_text(statement, 1, path1, path_len1, SQLITE_STATIC);
			//fprintf(stderr, "bind1: %d\n", r);
			r = sqlite3_bind_text(statement, 2, path2, path_len2, SQLITE_STATIC);
			//fprintf(stderr, "bind2: %d\n", r);

			r = sqlite3_step(statement);
			//fprintf(stderr, "step: %d\n", r);
			//fprintf(stderr, sqlite3_errmsg(db));
			// TODO: sqlite3_clear_bindings (maybe reset?), and finalize at end
			r = sqlite3_finalize(statement);
			//fprintf(stderr, "finalize: %d\n", r);
			//fprintf(stderr, "\n");
			//r = sqlite3_close(db);
			//fprintf(stderr, "close: %d\n", r);
		}
	}
}

int main(void)
{
	struct pollfd *pfd;
	sqlite3 *db;
	int r, fd;

	/* TODO: create db during installation so it gets cleaned up
	 * create table if not exists paths
	 * (path, exe, primary key (path, exe))
	 * without rowid;
	 */
	r = sqlite3_open("/var/lib/crumb/crumb.db", &db);
	if (r != SQLITE_OK) {
		fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errmsg(db));
		exit(EXIT_FAILURE);
	}

	fd = fanotify_init(FAN_CLASS_NOTIF, O_LARGEFILE);
	if (fd < 0) {
		perror("fanotify_init");
		exit(EXIT_FAILURE);
	}

	r = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_CLOSE_WRITE, -1, "/home");
	if (r < 0) {
		perror("fanotify_mark");
		exit(EXIT_FAILURE);
	}

	pfd->fd = fd;
	pfd->events = POLLIN;

	fprintf(stderr, "Listening for events.\n");

	for (;;) {
		r = poll(pfd, 1, -1);
		if (r < 0) {
			if (errno == EINTR)
				continue;

			perror("poll");
			exit(EXIT_FAILURE);
		}

		if (pfd->revents & POLLIN)
			store_event(fd, db);
	}
}
