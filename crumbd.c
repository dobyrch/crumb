#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <unistd.h>

#define FAN_CREATE             0x00000100      /* Subfile was created */
#define FAN_MARK_FILESYSTEM    0x00000100
#define FAN_REPORT_FID         0x00000200      /* Report unique file id */
#define FAN_REPORT_FILENAME    0x00000400      /* Report file name */

#define FAN_EVENT_INFO_TYPE_FID		1

/* Variable length info record following event metadata */
struct fanotify_event_info_header {
	__u8 info_type;
	__u8 pad;
	__u16 len;
};

/* Unique file identifier info record */
struct fanotify_event_info_fid {
	struct fanotify_event_info_header hdr;
	__kernel_fsid_t fsid;
	/*
	 * Following is an opaque struct file_handle that can be passed as
	 * an argument to open_by_handle_at(2).
	 */
	unsigned char handle[0];
};

#define BUF_SIZE 4096

void process_fanotify(int);
void process_inotify(int);

int main(int argc, char **argv)
{
	int fd, fdi, ret;
	struct pollfd fds[2];

	fdi = inotify_init();
	ret = inotify_add_watch(fdi, "/home/dobyrch/.mozilla/firefox/joc9538c.default-1521425002138", IN_CREATE);
	if (ret == -1) {
		perror("inotify_add_watch");
		exit(EXIT_FAILURE);
	}


	/* Create an fanotify file descriptor with FAN_REPORT_FID as a flag
	 * so that program can receive fid events.
	 */
	fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_FILENAME, 0);
	if (fd == -1) {
		perror("fanotify_init");
		exit(EXIT_FAILURE);
	}

	/* Place a mark on the filesystem object supplied in argv[1]. */
	ret = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
						FAN_CREATE | FAN_ONDIR,
						AT_FDCWD, "/home/dobyrch/");
	if (ret == -1) {
		perror("fanotify_mark");
		exit(EXIT_FAILURE);
	}

	printf("Listening for events.\n");

	fds[0].fd = fd;
	fds[1].fd = fdi;
	fds[0].events = POLLIN;
	fds[1].events = POLLIN;

	for (;;) {
		ret = poll(fds, 2, -1);
		if (ret == -1) {
			perror("poll");
			exit(EXIT_FAILURE);
		}

		if (fds[0].revents & POLLIN) {
			process_fanotify(fds[0].fd);
		} else if (fds[1].revents & POLLIN) {
			process_inotify(fds[1].fd);
		} else {
			assert(false);
		}
	}
}

void process_inotify(int fd) {
	char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *event;
	int i;
	ssize_t len;
	char *ptr;

	/* Read some events. */

	len = read(fd, buf, sizeof buf);
	if (len == -1 && errno != EAGAIN) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	/* If the nonblocking read() found no events to read, then
	   it returns -1 with errno set to EAGAIN. In that case,
	   we exit the loop. */

	if (len <= 0)
		return;

	/* Loop over all events in the buffer */

	for (ptr = buf; ptr < buf + len;
			ptr += sizeof(struct inotify_event) + event->len) {

		event = (const struct inotify_event *) ptr;

		if ((event->mask & IN_CREATE) == 0)
			return;

		/* Print the name of the file */

		if (event->len)
			printf("I: %s ", event->name);

		/* Print type of filesystem object */

		if (event->mask & IN_ISDIR)
			printf("[directory]\n");
		else
			printf("[file]\n");
	}
}

void process_fanotify(int fd) {
	int ret;
	ssize_t len, path_len, exe_path_len;
	char *filename;
	char path[PATH_MAX];
	char exe_path[PATH_MAX];
	char procfd_path[PATH_MAX];
	char procexe_path[PATH_MAX];
	char events_buf[BUF_SIZE];

	struct file_handle *file_handle;
	struct fanotify_event_metadata *metadata;
	struct fanotify_event_info_fid *fid;

	/* Read events from the event queue into a buffer */
	len = read(fd, (void *) &events_buf, sizeof(events_buf));
	if (len == -1 && errno != EAGAIN) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	/* Process all events within the buffer */
	for (metadata = (struct fanotify_event_metadata *) events_buf;
			FAN_EVENT_OK(metadata, len);
			metadata = FAN_EVENT_NEXT(metadata, len)) {



		/* Print the exe that created the new file/dir */
		snprintf(procexe_path, sizeof(procexe_path),
				"/proc/%d/exe", metadata->pid);
		exe_path_len = readlink(procexe_path, exe_path,
				sizeof(exe_path) - 1);
		if (exe_path_len != -1) {
			exe_path[exe_path_len] = '\0';
		}

		printf("Creator: %s (pid %d)\n", exe_path, metadata->pid);



		fid = (struct fanotify_event_info_fid *) (metadata + 1);
		file_handle = (struct file_handle *) fid->handle;
		filename = (char *) (file_handle + 1);
		// What is this extra stuff?
		filename += 8;

		/*
		printf("Filename: %s\n", filename);
		printf("ptrdiff: %ld\n", filename - (char *)metadata);
		printf("event_len: %u\n", metadata->event_len);
		printf("sizeof metadata: %ld\n", sizeof(struct fanotify_event_metadata));
		printf("sizeof fid: %ld\n", sizeof(struct fanotify_event_info_fid));
		printf("sizeof handle: %ld\n", sizeof(struct file_handle));
		*/

		/* Ensure that the event info is of the correct type */
		if (fid->hdr.info_type != FAN_EVENT_INFO_TYPE_FID) {
			fprintf(stderr, "Received unexpected event type.\n");
			exit(EXIT_FAILURE);
		}

		/*
		printf("====START\n");
		for (int x = 0; x < metadata->event_len; ++x) {
			unsigned char cc = ((char *)metadata)[x];

			if (cc < 33)
				printf("0x%02X\n", cc);
			else
				printf("%c\n", cc);
		}
		printf("=====STOP\n");
		*/

		/* metadata->fd is set to FAN_NOFD when FAN_REPORT_FID is enabled.
		 * To obtain a file descriptor for the file object corresponding to
		 * an event you can use the struct file_handle that's provided
		 * within the fanotify_event_info_fid in conjunction with the
		 * open_by_handle_at(2) system call. A check for -ESTALE is done
		 * to accommodate for the situation where the file handle was
		 * deleted for the object prior to this system call.
		 */
		//printf("metadata->fd: %d\n", metadata->fd);
		fd = open_by_handle_at(AT_FDCWD, file_handle, O_RDONLY);
		if (ret == -1 && errno == ESTALE) {
			printf("File handle is no longer valid. File has been deleted\n");
			continue;
		} else if (ret == -1) {
			perror("open_by_handle_at");
			exit(EXIT_FAILURE);
		}

		snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", fd);

		/* Retreive and print the path of the modified dentry */
		path_len = readlink(procfd_path, path, sizeof(path) - 1);
		if (path_len == -1) {
			perror("readlink");
			exit(EXIT_FAILURE);
		}

		path[path_len] = '/';
		/* TODO: check bounds */
		strcpy(&path[path_len+1], filename);
		/*
		printf("F: %s ", path);
		*/

		/*
		if (metadata->mask == FAN_CREATE)
			printf("[file]\n");

		if (metadata->mask == (FAN_CREATE | FAN_ONDIR))
			printf("[directory]\n");
		*/

		/* Close associated file decriptor for this event */
		close(fd);

		/*
		printf("==START\n");
		for (char *c = path; *c != '\0'; ++c) {
			if (*c)
				putchar(*c);
			else
				putchar('*');
		}
		printf("\n===STOP\n");
		*/

		printf("Created: %s\n\n", path);
	}
}
